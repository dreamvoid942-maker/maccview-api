"""Live OHLCV fetcher — source priority ported from GoldTerminal_CombatHUD.

Crypto  -> Binance klines (no key, limit 150)
Forex/metals -> TwelveData time_series (key) else Oanda candles (token+account)
Index (NAS100) -> TwelveData (NDX)

Returns (rows, source, last_close). Rows are [open, high, low, close, volume].
Raises RuntimeError(reason) when no source is configured — callers fall back
to deterministic demo data and MUST surface source:"demo" + the reason.
"""
import time

import requests

from ..config import settings

BINANCE_KLINES = "https://api.binance.com/api/v3/klines"
TD_SERIES = "https://api.twelvedata.com/time_series"

SYMBOLS = {
    "BTCUSD": {"kind": "crypto", "binance": "BTCUSDT", "td": "BTC/USD", "dec": 2},
    "EURUSD": {"kind": "forex", "td": "EUR/USD", "oanda": "EUR_USD", "dec": 5},
    "GBPJPY": {"kind": "forex", "td": "GBP/JPY", "oanda": "GBP_JPY", "dec": 3},
    "GBPUSD": {"kind": "forex", "td": "GBP/USD", "oanda": "GBP_USD", "dec": 5},
    "XAUUSD": {"kind": "metal", "td": "XAU/USD", "oanda": "XAU_USD", "dec": 2},
    "XAGUSD": {"kind": "metal", "td": "XAG/USD", "oanda": "XAG_USD", "dec": 4},
    # NAS100 -> QQQ, not NDX. TwelveData gates the raw index (NDX) behind its
    # Grow/Venture plans and answers 404 on this account, which made every
    # NAS100 forecast fail. QQQ is the Invesco Nasdaq-100 tracker: same
    # underlying index, free tier, and it returns the 520+ bars the model needs.
    "NAS100": {"kind": "index", "td": "QQQ", "dec": 2},
}

# Maccview TF -> per-source interval/granularity.
TF_MAP = {
    "M15": {"binance": "15m", "td": "15min", "oanda": "M15"},
    "1H": {"binance": "1h", "td": "1h", "oanda": "H1"},
    "H1": {"binance": "1h", "td": "1h", "oanda": "H1"},
    "4H": {"binance": "4h", "td": "4h", "oanda": "H4"},
    "H4": {"binance": "4h", "td": "4h", "oanda": "H4"},
    "1D": {"binance": "1d", "td": "1day", "oanda": "D"},
    "D1": {"binance": "1d", "td": "1day", "oanda": "D"},
    "1W": {"binance": "1w", "td": "1week", "oanda": "W"},
    "W1": {"binance": "1w", "td": "1week", "oanda": "W"},
}


def _sanitize(msg: str, limit: int = 160) -> str:
    """Redact secrets from error strings — never leak keys in responses."""
    import re

    s = str(msg or "")
    # Redact query-string / json api keys and bearer tokens.
    s = re.sub(r"(?i)(apikey\s*[:=]\s*)[^&\s'\"]+", r"\1[REDACTED]", s)
    s = re.sub(r"(?i)(api_key\s*[:=]\s*)[^&\s'\"]+", r"\1[REDACTED]", s)
    s = re.sub(r"(?i)(token\s*[:=]\s*)[^&\s'\"]+", r"\1[REDACTED]", s)
    s = re.sub(r"apikey=[^&\s'\"]*", "apikey=[REDACTED]", s)
    s = re.sub(r"token=[^&\s'\"]*", "token=[REDACTED]", s)
    s = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", s)
    return s[:limit]


def _get(url, **kw):
    """GET with one retry — TwelveData free tier throttles bursty calls."""
    try:
        r = requests.get(url, **kw)
        r.raise_for_status()
        return r
    except (requests.ConnectionError, requests.Timeout):
        time.sleep(8)
        r = requests.get(url, **kw)
        r.raise_for_status()
        return r


def _td_range(symbol: str, interval: str, start_ts: int, end_ts: int):
    import datetime
    fmt = lambda ts: datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    params = {"symbol": SYMBOLS[symbol]["td"], "interval": interval,
              "start_date": fmt(start_ts), "end_date": fmt(end_ts),
              "outputsize": 500, "apikey": settings.TWELVEDATA_KEY, "format": "JSON"}
    data = _get(TD_SERIES, params=params, timeout=12).json()
    if data.get("status") == "error":
        raise RuntimeError(f"twelvedata: {data.get('message', 'error')}")
    vals = data.get("values") or []
    rows = [[float(v["open"]), float(v["high"]), float(v["low"]), float(v["close"]),
             float(v.get("volume") or 0)] for v in reversed(vals)]
    if not rows:
        raise RuntimeError("twelvedata: empty range")
    return rows, "twelvedata"


def _oanda_range(symbol: str, granularity: str, start_ts: int, end_ts: int):
    inst = SYMBOLS[symbol]["oanda"]
    url = f"{_oanda_host()}/v3/instruments/{inst}/candles"
    data = _get(url, params={"granularity": granularity, "from": str(start_ts),
                             "to": str(min(end_ts, int(time.time()))), "price": "M",
                             "includeFirst": "false"},
                headers={"Authorization": f"Bearer {settings.OANDA_TOKEN}"},
                timeout=12).json()
    rows = []
    for c in data.get("candles", []):
        if not c.get("complete", True):
            continue
        m = c["mid"]
        rows.append([float(m["o"]), float(m["h"]), float(m["l"]), float(m["c"]), float(c.get("volume", 0))])
    if not rows:
        raise RuntimeError("oanda: empty range")
    return rows, "oanda"


def _binance_range(symbol: str, interval: str, start_ts: int, end_ts: int):
    params = {"symbol": SYMBOLS[symbol]["binance"], "interval": interval,
              "startTime": start_ts * 1000, "endTime": min(end_ts, int(time.time())) * 1000, "limit": 1000}
    data = _get(BINANCE_KLINES, params=params, timeout=12).json()
    rows = [[float(k[1]), float(k[2]), float(k[3]), float(k[4]), float(k[5])] for k in data]
    if not rows:
        raise RuntimeError("binance: empty range")
    return rows, "binance"


def fetch_ohlcv_range(symbol: str, follow_tf: str, start_ts: int, end_ts: int):
    """Candles strictly inside [start_ts, end_ts] for outcome realization.
    Cached (closed windows never change). Raises RuntimeError when unavailable."""
    symbol = (symbol or "").upper().replace("/", "")
    if symbol not in SYMBOLS:
        raise RuntimeError(f"unsupported symbol {symbol}")
    key = ("range", symbol, follow_tf, start_ts, end_ts)
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < 3600:
        return hit[1], hit[2]
    kind = SYMBOLS[symbol]["kind"]
    errors = []
    if kind == "crypto":
        for fn, iv in ((_binance_range, TF_MAP[follow_tf]["binance"] if follow_tf in TF_MAP else "1h"),
                       (_td_range, TF_MAP[follow_tf]["td"] if follow_tf in TF_MAP else "1h")):
            try:
                if fn is _td_range and not settings.TWELVEDATA_KEY:
                    continue
                rows, src = fn(symbol, iv, start_ts, end_ts)
                _CACHE[key] = (time.time(), rows, src)
                return rows, src
            except Exception as e:
                errors.append(f"{fn.__name__}: {e}")
    else:
        if settings.TWELVEDATA_KEY:
            try:
                rows, src = _td_range(symbol, TF_MAP[follow_tf]["td"] if follow_tf in TF_MAP else "1h",
                                      start_ts, end_ts)
                _CACHE[key] = (time.time(), rows, src)
                return rows, src
            except Exception as e:
                errors.append(str(e))
        if settings.OANDA_TOKEN and "oanda" in SYMBOLS[symbol]:
            try:
                rows, src = _oanda_range(symbol, TF_MAP[follow_tf]["oanda"] if follow_tf in TF_MAP else "H1",
                                         start_ts, end_ts)
                _CACHE[key] = (time.time(), rows, src)
                return rows, src
            except Exception as e:
                errors.append(f"oanda: {e}")
    raise RuntimeError("; ".join(errors) or "no range source")


# In-memory candle cache: H1 candles barely move within minutes, and the
# TwelveData free tier rate-limits bursty calls. Keyed (symbol, tf).
_CACHE: dict = {}
CACHE_TTL = 300


def _oanda_host() -> str:
    env = (settings.OANDA_ENV or "practice").lower()
    return "https://api-fxtrade.oanda.com" if env == "live" else "https://api-fxpractice.oanda.com"


def _binance(symbol: str, interval: str, n: int):
    params = {"symbol": SYMBOLS[symbol]["binance"], "interval": interval, "limit": max(n, 10)}
    r = requests.get(BINANCE_KLINES, params=params, timeout=10)
    r.raise_for_status()
    rows = [[float(k[1]), float(k[2]), float(k[3]), float(k[4]), float(k[5])] for k in r.json()]
    return rows, "binance"


def _twelvedata(symbol: str, interval: str, n: int):
    params = {
        "symbol": SYMBOLS[symbol]["td"],
        "interval": interval,
        # 5000, not 500. The Goose Feather window needs MIN_BARS+1 = 517 closed
        # candles, so a 500 cap made every forecast fail with
        # "need 516 bars, got 500" no matter what n the caller asked for.
        # TwelveData's time_series endpoint serves up to 5000 per request.
        "outputsize": min(max(n, 10), 5000),
        "apikey": settings.TWELVEDATA_KEY,
        "format": "JSON",
    }
    # 25s, not 10s. A 5000-bar request measured 15.4s on this account, and the
    # Goose Feather window asks for >=517 bars. A 10s ceiling turned a slow-but-
    # working upstream into a hard forecast failure.
    r = _get(TD_SERIES, params=params, timeout=25)
    data = r.json()
    if data.get("status") == "error":
        raise RuntimeError(f"twelvedata: {data.get('message', 'error')}")
    vals = data.get("values") or []
    rows = [[float(v["open"]), float(v["high"]), float(v["low"]), float(v["close"]),
             float(v.get("volume") or 0)] for v in reversed(vals)]
    if not rows:
        raise RuntimeError("twelvedata: empty series")
    return rows, "twelvedata"


def _oanda(symbol: str, granularity: str, n: int):
    inst = SYMBOLS[symbol]["oanda"]
    url = f"{_oanda_host()}/v3/instruments/{inst}/candles"
    r = requests.get(
        url,
        params={"granularity": granularity, "count": min(max(n, 10), 500), "price": "M"},
        headers={"Authorization": f"Bearer {settings.OANDA_TOKEN}"},
        timeout=10,
    )
    r.raise_for_status()
    rows = []
    for c in r.json().get("candles", []):
        if not c.get("complete", True):
            continue
        m = c["mid"]
        rows.append([float(m["o"]), float(m["h"]), float(m["l"]), float(m["c"]), float(c.get("volume", 0))])
    if not rows:
        raise RuntimeError("oanda: empty candles")
    return rows, "oanda"


def fetch_ohlcv(symbol: str, timeframe: str = "H1", n: int = 120):
    """Fetch up to n candles. Returns (rows, source, last_close)."""
    symbol = (symbol or "").upper().replace("/", "")
    if symbol not in SYMBOLS:
        raise RuntimeError(f"unsupported symbol {symbol}")
    tf = TF_MAP.get((timeframe or "H1").upper(), TF_MAP["H1"])
    key = (symbol, _tf_name(tf), n)
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        rows, src = hit[1], hit[2]
        return rows, src, rows[-1][3]
    rows, src, last = _fetch_fresh(symbol, tf, n)
    if len(rows) > n:
        rows = rows[-n:]
    _CACHE[key] = (time.time(), rows, src)
    return rows, src, rows[-1][3]


def _tf_name(tf: dict) -> str:
    for k, v in TF_MAP.items():
        if v == tf:
            return k
    return "H1"


def _fetch_fresh(symbol: str, tf: dict, n: int):
    kind = SYMBOLS[symbol]["kind"]
    errors = []

    if kind == "crypto":
        try:
            rows, src = _binance(symbol, tf["binance"], n)
            return rows, src, rows[-1][3]
        except Exception as e:  # Binance down? Try TwelveData as backup.
            errors.append(_sanitize(f"binance: {e}", 160))
            if settings.TWELVEDATA_KEY:
                try:
                    rows, src = _twelvedata(symbol, tf["td"], n)
                    return rows, src, rows[-1][3]
                except Exception as e2:
                    errors.append(_sanitize(str(e2), 160))
    else:
        if settings.TWELVEDATA_KEY:
            try:
                rows, src = _twelvedata(symbol, tf["td"], n)
                return rows, src, rows[-1][3]
            except Exception as e:
                errors.append(_sanitize(str(e), 160))
        if settings.OANDA_TOKEN and "oanda" in SYMBOLS[symbol]:
            try:
                rows, src = _oanda(symbol, tf["oanda"], n)
                return rows, src, rows[-1][3]
            except Exception as e:
                errors.append(_sanitize(f"oanda: {e}", 160))

    missing = []
    if kind != "crypto" and not settings.TWELVEDATA_KEY and not settings.OANDA_TOKEN:
        missing.append("set TWELVEDATA_KEY or OANDA_TOKEN+OANDA_ACCOUNT")
    raise RuntimeError("; ".join(errors + missing) or "no market source")
