"""Forecast engine — Goose Feather 1.6 Summit, scored in Maccview's own Worker.

  GET  {MACCVIEW_MODEL_URL}/health   -> {"ok": true, ...}
  POST {MACCVIEW_MODEL_URL}/score    -> {"p": 0.63, "action": "long", ...}

The vector contract is exact and shared with the Python reference engine:
48 base features -> window_stats over the last 256 rows -> 192 floats.
Bars come from services.marketdata (ALOD relay for FX/metals/indices,
TwelveData/Oanda as fallbacks, Binance keyless for crypto).

Every response carries live:bool + source:str so the app can badge LIVE vs
DEMO honestly. Nothing is ever presented as live when it is not.
"""
import hashlib
import json
import os
import time

import requests
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from ..config import settings
from ..database import backend, get_db, model_cost, table_columns
from ..routers.auth import require_session
from ..services.marketdata import SYMBOLS, fetch_ohlcv, fetch_ohlcv_range

router = APIRouter(prefix="/oracle", tags=["oracle"])

# Credit costs live in the `models` catalogue, not in code — a price change or
# a new model release is a row update via /admin/models, no deploy needed.
# These constants are only fallbacks for the case where the catalogue row is
# missing entirely (a fresh DB before seed(), or a deleted key).
FORECAST_MODEL_KEY = "oracle-vision-1"
FORECAST_COST_FALLBACK = 1
SCAN_MODEL_KEYS = {
    "mini": "scan-mini",
    "moderate": "scan-moderate",
    "max": "scan-max",
}
SCAN_COST_FALLBACKS = {"mini": 5, "moderate": 10, "max": 15}


def forecast_cost(conn) -> int:
    """Live credit cost for a forecast, read from the catalogue."""
    return model_cost(conn, FORECAST_MODEL_KEY, FORECAST_COST_FALLBACK)


def scan_cost(conn, mode: str) -> int:
    """Live credit cost for a deep scan at the given depth."""
    key = SCAN_MODEL_KEYS.get(mode, SCAN_MODEL_KEYS["mini"])
    return model_cost(conn, key, SCAN_COST_FALLBACKS.get(mode, SCAN_COST_FALLBACKS["mini"]))


def forecast_model_name(conn) -> str:
    """Display name for the model doing the work, for the reason string."""
    row = conn.execute(
        "SELECT name FROM models WHERE key=?", (FORECAST_MODEL_KEY,)
    ).fetchone()
    return (row["name"] if row else "") or "Oracle Vision"

BASE_PRICES = {
    "EURUSD": 1.0852,
    "GBPJPY": 191.44,
    "GBPUSD": 1.2732,
    "XAUUSD": 2384.10,
    "XAGUSD": 28.42,
    "BTCUSD": 67210.0,
    "NAS100": 18240.5,
}

SCAN_UNIVERSE = ["XAUUSD", "BTCUSD", "EURUSD", "NAS100", "GBPJPY", "XAGUSD"]

RUNTIME_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "oracle.json")
# Legacy/alternate location (backend/data) — read as fallback so a runtime
# URL saved under either layout still wins over env.
RUNTIME_FILE_ALT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "oracle.json")


def _norm_email(email: str) -> str:
    return (email or "demo@maccview.app").strip().lower() or "demo@maccview.app"


def _sanitize(msg: str, limit: int = 160) -> str:
    """Redact secrets/keys from error strings shown to clients."""
    import re

    s = str(msg or "")
    # Hide any embedded oracle/market URL credentials and api keys.
    try:
        eff = effective_oracle_url()
        if eff and eff in s:
            s = s.replace(eff, mask_url(eff))
    except Exception:
        pass
    s = re.sub(r"(?i)(apikey\s*[:=]\s*)[^&\s'\"]+", r"\1[REDACTED]", s)
    s = re.sub(r"apikey=[^&\s'\"]*", "apikey=[REDACTED]", s)
    s = re.sub(r"token=[^&\s'\"]*", "token=[REDACTED]", s)
    s = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", s)
    return s[:limit]


class ForecastIn(BaseModel):
    asset: str = "XAUUSD"
    timeframe: str = "H1"
    email: str = "demo@maccview.app"
    n_candles: int = 120


class DeepScanIn(BaseModel):
    mode: str = "moderate"  # mini | moderate | max
    email: str = "demo@maccview.app"


class OracleConfigIn(BaseModel):
    oracle_url: str = ""


# Outcome realization: score saved forecasts against what price DID next.
# Windows per forecast timeframe (seconds to look ahead for first touch).
REALIZE_WINDOWS = {"M15": 172800, "H1": 172800, "H4": 1209600, "D1": 2592000, "W1": 7257600}
# Follow-up granularity per TF (keeps every window <= 500 candles).
FOLLOW_TF = {"M15": "M15", "H1": "H1", "H4": "H1", "D1": "H4", "W1": "D1"}


def _ensure_outcome_cols(conn) -> None:
    """Additive column repair — SQLite only.

    Postgres carries these columns from supabase_schema.sql, and adding them at
    runtime there would need DDL rights the app should not hold.
    """
    try:
        if backend() == "postgres":
            return
        cols = table_columns(conn, "forecasts")
        if "outcome" not in cols:
            conn.execute("ALTER TABLE forecasts ADD COLUMN outcome TEXT DEFAULT 'open'")
        if "decided_at" not in cols:
            conn.execute("ALTER TABLE forecasts ADD COLUMN decided_at INTEGER DEFAULT 0")
        conn.commit()
    except Exception:
        pass


def decide_outcome(asset: str, direction: str, entry: float, tp: float, sl: float,
                   after_ts: int, timeframe: str) -> dict:
    """First-touch walk-forward: which level did price touch first AFTER entry?
    Same-candle ambiguity resolves conservatively (against the call)."""
    tf = _norm_tf(timeframe)
    window_s = REALIZE_WINDOWS.get(tf, 172800)
    follow = FOLLOW_TF.get(tf, "H1")
    rows, _ = fetch_ohlcv_range(asset, follow, after_ts, after_ts + window_s)
    return _walk(direction, entry, tp, sl, rows)


def _walk(direction: str, entry: float, tp: float, sl: float, rows: list) -> dict:
    buy = (direction or "").upper() == "BUY"
    for i, r in enumerate(rows):
        hi, lo = r[1], r[2]
        if buy:
            hit_tp, hit_sl = hi >= tp, lo <= sl
        else:
            hit_tp, hit_sl = lo <= tp, hi >= sl
        if hit_tp and hit_sl:
            return {"outcome": "sl", "candles": i + 1, "note": "both touched same candle"}
        if hit_tp:
            return {"outcome": "tp", "candles": i + 1}
        if hit_sl:
            return {"outcome": "sl", "candles": i + 1}
    return {"outcome": "open", "candles": len(rows)}


def _norm_tf(tf: str) -> str:
    t = (tf or "H1").upper()
    return {"1H": "H1", "4H": "H4", "1D": "D1", "1W": "W1"}.get(t, t)


def effective_oracle_url() -> str:
    """The model host. Runtime override removed with the Oracle Vision tunnel.

    It used to read data/oracle.json first and fall back to env, which meant a
    URL saved from the app outranked the deployment config. That file is no
    longer read; MACCVIEW_MODEL_URL is the single source of truth.
    """
    return (settings.MACCVIEW_MODEL_URL or "").strip().rstrip("/")


def mask_url(url: str) -> str:
    if not url:
        return ""
    try:
        host = url.split("://", 1)[1].split("/", 1)[0]
        return f"…{host[-24:]}" if len(host) > 24 else host
    except Exception:
        return "set"


def oracle_health(timeout: int = 8) -> dict:
    """Is the model gateway reachable?

    The old implementation dialled an external Oracle service over ngrok. There
    is no external service any more — the only thing that can be down is the
    Summit Worker, so that is the only thing probed.
    """
    from ..services.model_gateway import ModelGateway, GatewayError

    base = (settings.MACCVIEW_MODEL_URL or "").strip().rstrip("/")
    if not base:
        return {"configured": False, "live": False,
                "detail": "MACCVIEW_MODEL_URL not set",
                "oracle_url": ""}
    try:
        gw = ModelGateway(base, settings.LW_MODEL, timeout=float(timeout))
        h = gw.health()
        return {"configured": True, "live": bool(h.get("ok")),
                "model_status": "healthy" if h.get("ok") else "unhealthy",
                "detail": "gateway healthy" if h.get("ok") else "gateway unhealthy",
                "oracle_url": mask_url(base)}
    except Exception as e:
        return {"configured": True, "live": False,
                "detail": _sanitize(f"{type(e).__name__}: {e}"),
                "oracle_url": mask_url(base)}


def oracle_predict(ohlcv: list, symbol: str, timeout: int = 30) -> dict:
    """Removed with the Oracle Vision tunnel.

    Kept as a hard error rather than deleted so that any caller still holding a
    reference fails loudly instead of silently returning a blank forecast. The
    live path is _live_forecast(), which scores with Summit.
    """
    raise RuntimeError("Oracle Vision tunnel is retired; forecasts run on the "
                       "Goose Feather gateway (see _live_forecast)")


def _px(d: dict, *keys) -> float:
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)) and v > 0:
            return float(v)
    return 0.0


def _atr(rows: list, n: int = 14) -> float:
    try:
        trs = [abs(r[1] - r[2]) for r in rows[-n:] if len(r) >= 4]
        return sum(trs) / len(trs) if trs else 0.0
    except Exception:
        return 0.0


def map_oracle_to_forecast(asset: str, timeframe: str, cur: float, data: dict,
                           dec: int, rows: list | None = None) -> dict:
    """GoldTerminal summary -> trade plan. Direction/confidence/regime come
    from the model; TP/SL come from 14-candle ATR because the model's
    absolute price levels (close_mean/high_mean/low_mean) are uncalibrated
    for order placement (std often exceeds the level itself)."""
    s = data.get("summary", {}) or {}
    trend = (s.get("trend_direction") or "").lower()
    direction = "BUY" if trend == "up" else "SELL"

    conf_raw = s.get("avg_direction_confidence")
    try:
        conf_raw = float(conf_raw)
    except (TypeError, ValueError):
        conf_raw = 0.5
    if conf_raw > 1:  # tolerate percent-scale backends
        conf_raw /= 100.0
    confidence = round(max(1.0, min(99.0, conf_raw * 100.0)), 1)

    atr = _atr(rows or [])
    if atr <= 0:
        atr = cur * 0.002
    entry = round(cur, dec)
    if direction == "BUY":
        tp = round(entry + 1.5 * atr, dec)
        sl = round(entry - 1.0 * atr, dec)
    else:
        tp = round(entry - 1.5 * atr, dec)
        sl = round(entry + 1.0 * atr, dec)

    risk_score = (float(s.get("avg_collapse_risk") or 0) + float(s.get("avg_reversal_risk") or 0)) / 2.0
    risk = "low" if risk_score < 0.3 else ("medium" if risk_score < 0.6 else "high")
    regime = s.get("regime_dominant") or s.get("vol_regime") or "unknown"
    vol = s.get("vol_regime") or ""
    mag = s.get("dominant_magnitude") or ""
    notes = " ".join(p for p in [
        f"Volatility {vol}." if vol and vol != "unknown" else "",
        f"Move looks {mag}." if mag and mag != "unknown" else "",
    ] if p)
    return {
        "asset": asset, "timeframe": timeframe, "direction": direction,
        "entry": entry, "tp": tp, "sl": sl, "take_profit": tp, "stop_loss": sl,
        "confidence": confidence, "expected_move": round(abs(tp - entry), dec),
        "horizon": timeframe, "regime": regime, "risk": risk, "risk_level": risk,
        "explanation": (
            f"Oracle Vision sees {direction} on {asset} ({timeframe}): "
            f"{regime} regime, {confidence}% directional confidence. {notes}"
        ).strip(),
    }


def _mock_forecast(asset: str, timeframe: str) -> dict:
    asset = (asset or "XAUUSD").upper()
    seed = int(hashlib.sha256(f"{asset}:{timeframe}".encode()).hexdigest()[:8], 16)
    direction = "BUY" if seed % 2 == 0 else "SELL"
    base = BASE_PRICES.get(asset, 100.0)
    spread = base * (0.004 if asset in ("BTCUSD", "NAS100", "XAUUSD") else 0.0015)
    entry = round(base, 4 if base < 5000 else 2)
    sign = 1 if direction == "BUY" else -1
    tp = round(entry + sign * spread * 2.0, 4 if base < 5000 else 2)
    sl = round(entry - sign * spread * 1.0, 4 if base < 5000 else 2)
    confidence = round(62 + (seed % 34) + (seed % 100) / 100.0, 1)
    regime = ["trending", "ranging", "breakout"][seed % 3]
    risk = ["low", "medium", "high"][(seed // 7) % 3]
    return {
        "asset": asset, "timeframe": timeframe, "direction": direction,
        "entry": entry, "tp": tp, "sl": sl, "take_profit": tp, "stop_loss": sl,
        "confidence": confidence, "expected_move": round(abs(tp - entry), 4 if base < 5000 else 2),
        "horizon": timeframe, "regime": regime, "risk": risk, "risk_level": risk,
        "explanation": f"DEMO — Oracle backend not connected. Illustrative {direction} on {asset} ({timeframe}).",
    }


def _charge(conn, email: str, delta: int, reason: str) -> int:
    """Apply a credit delta through the audited ledger writer.

    Returns the new balance. Raises InsufficientCredits when a spend would
    take the account below zero. Never fabricates an account: an unknown
    email is an error, not a new user.
    """
    from ..database import move_credits

    email = _norm_email(email)
    try:
        return move_credits(conn, email, delta, reason)
    except KeyError:
        raise InsufficientCredits("no account for this identity")
    except ValueError:
        raise InsufficientCredits("not enough credits")


class InsufficientCredits(Exception):
    """Raised when a spend exceeds the account balance."""


def _has_credits(email: str, cost: int) -> bool:
    """Server-side balance check. The only authority on affordability."""
    conn = get_db()
    try:
        row = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
        return bool(row) and int(row["credits"]) >= int(cost)
    finally:
        conn.close()


def _live_forecast(asset: str, timeframe: str, n: int) -> dict:
    """Forecast from Goose Feather 1.6 Summit.

    This used to POST candles to an external "Oracle Vision" service reached
    through an ngrok tunnel. That dependency is gone: the tunnel was a laptop
    process behind a free ngrok URL, so the app's forecasts died every time the
    laptop closed. Maccview now owns the whole path — ALOD relay for candles,
    the vendored feature engine, and Summit in the Cloudflare Worker.

    The vector contract is unchanged (48 features -> 192-float window ->
    /score), which is why this can drop in without touching the model.
    """
    from ..services.feather import MIN_BARS, feature_vector
    from ..services.model_gateway import ModelGateway, GatewayError, decision

    # One spare bar: matrix_from_bars drops the last, still-forming candle.
    need = MIN_BARS + 1
    rows, mkt_source, last = fetch_ohlcv(asset, timeframe, max(n, need))
    dec = SYMBOLS[asset]["dec"]

    # fetch_ohlcv returns [o,h,l,c,v] — five columns, no timestamp. The feature
    # engine's contract is [time,o,h,l,c,v]. Re-indexing here (rather than
    # changing the engine) keeps the vendored engine byte-identical to the
    # reference implementation; the timestamp is unused by every feature, so a
    # zero placeholder is honest rather than wrong.
    bars = [[i] + list(r[:5]) for i, r in enumerate(rows)]

    base = (settings.MACCVIEW_MODEL_URL or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("MACCVIEW_MODEL_URL not set")

    feats = feature_vector(bars)
    gw = ModelGateway(base, settings.LW_MODEL, timeout=25.0)
    res = gw.score(feats)
    p = res["p"]
    side = decision(p, settings.LW_CT)

    # STAND ASIDE is a real outcome, not an error. It maps to the app's
    # existing neutral shape rather than being coerced into a BUY/SELL.
    direction = "BUY" if side == "LONG" else ("SELL" if side == "SHORT" else "HOLD")
    confidence = round(max(0.0, min(100.0, abs(p - 0.5) * 200.0)), 1)

    atr = _atr(rows)
    if atr <= 0:
        atr = last * 0.002
    entry = round(last, dec)
    if direction == "BUY":
        tp, sl = round(entry + 1.5 * atr, dec), round(entry - 1.0 * atr, dec)
    elif direction == "SELL":
        tp, sl = round(entry - 1.5 * atr, dec), round(entry + 1.0 * atr, dec)
    else:
        tp, sl = entry, entry

    return {
        "asset": asset, "timeframe": _norm_tf(timeframe), "direction": direction,
        "entry": entry, "tp": tp, "sl": sl, "take_profit": tp, "stop_loss": sl,
        "confidence": confidence,
        "expected_move": round(abs(tp - entry), dec),
        "horizon": timeframe, "regime": "model", "risk": "medium", "risk_level": "medium",
        "probability": round(float(p), 4),
        "model": settings.LW_MODEL, "ct": settings.LW_CT, "verdict": side,
        "explanation": (
            f"{settings.LW_MODEL} scores {p:.3f} on {asset} ({_norm_tf(timeframe)}); "
            f"threshold {settings.LW_CT:.2f} -> {side}."
        ),
        "live": True,
        "source": f"feather+{mkt_source}",
    }


@router.get("/status")
def status():
    h = oracle_health()
    return {"oracle_url": mask_url(effective_oracle_url()), **h}


@router.get("/forecasts")
def forecast_history(limit: int = 20, authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    email = sess["email"]
    conn = get_db()
    try:
        _ensure_outcome_cols(conn)
        cur = conn.execute(
            "SELECT id,asset,timeframe,direction,entry,tp,sl,confidence,created_at,"
            " COALESCE(outcome,'open') AS outcome FROM forecasts"
            " WHERE user_email=? ORDER BY id DESC LIMIT ?",
            (email, max(1, min(limit, 100))),
        )
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"email": email, "count": len(rows), "forecasts": rows}


def realize_pending(email: str, limit: int = 6) -> list:
    """Score oldest undecided forecasts against realized price action.
    Network-bound decides run in parallel (4 workers); DB writes stay serial."""
    import concurrent.futures
    conn = get_db()
    decided = []
    try:
        _ensure_outcome_cols(conn)
        now = int(time.time())
        cur = conn.execute(
            "SELECT id,asset,timeframe,direction,entry,tp,sl,created_at FROM forecasts"
            " WHERE user_email=? AND COALESCE(outcome,'open')='open' AND created_at<?"
            " ORDER BY id ASC LIMIT ?",
            (email, now - 3600, max(1, min(limit, 12))),
        )
        pend = [dict(r) for r in cur.fetchall()]

        def _one(p):
            try:
                res = decide_outcome(p["asset"], p["direction"], p["entry"], p["tp"], p["sl"],
                                     p["created_at"], p["timeframe"])
                return {"id": p["id"], "asset": p["asset"], **res}
            except Exception as e:
                return {"id": p["id"], "asset": p["asset"], "outcome": "open",
                        "error": _sanitize(str(e), 100)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(_one, pend))
        for r in results:
            if r.get("outcome", "open") != "open" and "error" not in r:
                conn.execute("UPDATE forecasts SET outcome=?,decided_at=? WHERE id=?",
                             (r["outcome"], now, r["id"]))
                conn.commit()
            decided.append(r)
    finally:
        conn.close()
    return decided


@router.get("/realize")
def realize(limit: int = 6, authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    email = sess["email"]
    return {"email": email, "decided": realize_pending(email, limit)}


@router.get("/stats")
def stats(authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    email = sess["email"]
    realize_pending(email, 6)  # best-effort scoring before aggregating
    conn = get_db()
    try:
        _ensure_outcome_cols(conn)
        rows = [dict(r) for r in conn.execute(
            "SELECT asset,timeframe,confidence,created_at,COALESCE(outcome,'open') AS outcome"
            " FROM forecasts WHERE user_email=? ORDER BY id DESC LIMIT 500", (email,)).fetchall()]
    finally:
        conn.close()
    tp = sum(1 for r in rows if r["outcome"] == "tp")
    sl = sum(1 for r in rows if r["outcome"] == "sl")
    decided = tp + sl
    win_rate = round(tp / decided * 100.0, 1) if decided else 0.0
    avg_conf = round(sum(float(r["confidence"] or 0) for r in rows) / len(rows), 1) if rows else 0.0
    month = time.strftime("%Y-%m", time.gmtime())
    daily: dict = {}
    month_n = 0
    for r in rows:
        day = time.strftime("%Y-%m-%d", time.gmtime(r["created_at"] or 0))
        if not day.startswith(month):
            continue
        month_n += 1
        d = daily.setdefault(day, {"day": day[8:], "full": day, "count": 0, "tp": 0, "sl": 0})
        d["count"] += 1
        if r["outcome"] == "tp":
            d["tp"] += 1
        elif r["outcome"] == "sl":
            d["sl"] += 1
    return {
        "email": email, "total": len(rows), "decided": decided,
        "win_rate": win_rate, "tp": tp, "sl": sl, "open": len(rows) - decided,
        "avg_confidence": avg_conf,
        "month": month, "month_count": month_n,
        "daily": [daily[k] for k in sorted(daily)],
    }

@router.post("/config")
def set_config(body: OracleConfigIn):
    """Retired.

    This wrote a runtime override URL that took precedence over env, so a stale
    ngrok address saved from the Settings screen could silently outlive the
    tunnel. With the tunnel gone there is nothing to point at: the model host is
    MACCVIEW_MODEL_URL and it is set at deploy time, not from the app.
    """
    raise HTTPException(
        status_code=410,
        detail="oracle_url override retired; the model host is configured at deploy time",
    )


@router.post("/forecast")
def forecast(body: ForecastIn, authorization: str | None = Header(default=None)):
    # Identity comes from the session token, never from the request body.
    sess = require_session(authorization)
    email = sess["email"]
    asset = (body.asset or "XAUUSD").upper().replace("/", "")
    tf = _norm_tf(body.timeframe)

    # Cost is read from the catalogue at call time, so a price change applies
    # immediately without a restart or a client release.
    conn = get_db()
    try:
        cost = forecast_cost(conn)
        model_name = forecast_model_name(conn)
    finally:
        conn.close()

    # Spend is checked server-side BEFORE the work is done.
    if not _has_credits(email, cost):
        raise HTTPException(status_code=402, detail="not enough credits")

    live, source, reason = True, "", ""
    try:
        out = _live_forecast(asset, tf, max(32, min(body.n_candles or 120, 300)))
        source = out.pop("source")
    except Exception as e:
        reason = _sanitize(str(e))
        out = _mock_forecast(asset, tf)
        live, source = False, "demo"
    out["live"] = live
    out["source"] = source
    if not live:
        out["demo_reason"] = reason
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO forecasts(user_email,asset,timeframe,direction,entry,tp,sl,confidence,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (email, out["asset"], tf, out["direction"], out["entry"],
             out["tp"], out["sl"], out["confidence"], int(time.time())),
        )
        balance = _charge(conn, email, -cost, f"{model_name} {out['asset']} {tf} ({source})")
        conn.commit()
    except InsufficientCredits:
        conn.rollback()
        raise HTTPException(status_code=402, detail="not enough credits")
    finally:
        conn.close()
    out["credits"] = balance
    out["cost"] = cost
    out["model"] = FORECAST_MODEL_KEY
    return out


@router.post("/deep-scan")
def deep_scan(body: DeepScanIn, authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    email = sess["email"]
    mode = (body.mode or "moderate").lower()
    conn = get_db()
    try:
        cost = scan_cost(conn, mode)
    finally:
        conn.close()
    if not _has_credits(email, cost):
        raise HTTPException(status_code=402, detail="not enough credits")

    limits = {"mini": 5, "moderate": 10, "max": 6}
    tfs = {"mini": ["H4"], "moderate": ["H1", "H4"], "max": ["M15", "H1", "H4"]}
    tfs = tfs.get(mode, ["H4"])
    ranked = []
    for i, asset in enumerate(SCAN_UNIVERSE):
        tf = tfs[i % len(tfs)]
        try:
            f = _live_forecast(asset, tf, 64)
        except Exception as e:
            f = _mock_forecast(asset, tf)
            f["live"] = False
            f["source"] = "demo"
            f["demo_reason"] = _sanitize(str(e), 160)
        score = round(f["confidence"] + (len(SCAN_UNIVERSE) - i) * 0.5, 1)
        ranked.append({**f, "opportunity_score": score,
                       "trend_strength": round(50 + (score % 45), 1),
                       "expected_reward": f["expected_move"], "volatility": "medium"})
    ranked.sort(key=lambda r: r["opportunity_score"], reverse=True)
    ranked = ranked[: limits.get(mode, 5)]
    conn = get_db()
    try:
        conn.execute("INSERT INTO scans(user_email,mode,result,created_at) VALUES(?,?,?,?)",
                     (email, mode, json.dumps(ranked), int(time.time())))
        balance = _charge(conn, email, -cost, f"deep-scan {mode}")
        conn.commit()
    except InsufficientCredits:
        conn.rollback()
        raise HTTPException(status_code=402, detail="not enough credits")
    finally:
        conn.close()
    live_n = sum(1 for r in ranked if r.get("live"))
    # Top-level honesty flags (additive, backward compatible): live is True
    # only when every result is live; source is oracle/demo/mixed.
    if live_n == len(ranked) and len(ranked) > 0:
        top_source = ranked[0].get("source", "oracle")
    elif live_n == 0:
        top_source = "demo"
    else:
        top_source = "mixed"
    out = {"mode": mode, "results": ranked, "count": len(ranked),
           "live_count": live_n, "live": live_n == len(ranked) and len(ranked) > 0,
           "source": top_source, "credits": balance, "cost": cost,
           "model": SCAN_MODEL_KEYS.get(mode, SCAN_MODEL_KEYS["mini"])}
    if live_n != len(ranked):
        out["demo_reason"] = f"{len(ranked) - live_n}/{len(ranked)} results are demo (oracle or market unavailable)"
    return out
