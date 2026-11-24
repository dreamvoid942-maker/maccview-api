"""Static market asset list + live quotes + Finnhub news (honest unavailable state w/o key)."""
import re
import time

import requests
from fastapi import APIRouter

from ..config import settings
from ..services.marketdata import SYMBOLS, fetch_ohlcv

router = APIRouter(prefix="/market", tags=["market"])

ASSETS = [
    {"symbol": "EURUSD", "name": "Euro / US Dollar", "kind": "forex", "price": 1.0852},
    {"symbol": "GBPJPY", "name": "British Pound / Japanese Yen", "kind": "forex", "price": 191.44},
    {"symbol": "XAUUSD", "name": "Gold / US Dollar", "kind": "metal", "price": 2384.10},
    {"symbol": "XAGUSD", "name": "Silver / US Dollar", "kind": "metal", "price": 28.42},
    {"symbol": "BTCUSD", "name": "Bitcoin / US Dollar", "kind": "crypto", "price": 67210.0},
    {"symbol": "NAS100", "name": "Nasdaq 100 Index", "kind": "index", "price": 18240.5},
]


@router.get("/assets")
def assets():
    return {"assets": ASSETS}


@router.get("/quote")
def quote(asset: str = "XAUUSD"):
    """Live price + trailing-24-H1-candle high/low/change. Demo honesty flags included."""
    sym = (asset or "").upper().replace("/", "")
    if sym not in SYMBOLS:
        return {"asset": sym, "live": False, "source": "demo", "reason": "unsupported symbol"}
    try:
        rows, source, last = fetch_ohlcv(sym, "H1", 24)
    except Exception as e:
        msg = re.sub(r"apikey=[^&\s'\"]*", "apikey=[REDACTED]", str(e))
        msg = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", msg)
        return {"asset": sym, "live": False, "source": "demo", "reason": msg[:160]}
    highs = [r[1] for r in rows]
    lows = [r[2] for r in rows]
    first = rows[0][3]
    dec = SYMBOLS[sym]["dec"]
    return {
        "asset": sym, "live": True, "source": source, "price": round(last, dec),
        "high24": round(max(highs), dec), "low24": round(min(lows), dec),
        "change_pct": round((last - first) / first * 100.0, 2) if first else 0.0,
    }


@router.get("/news")
def news():
    if not settings.FINNHUB_KEY:
        return {"available": False, "reason": "FINNHUB_KEY not set", "items": []}
    try:
        r = requests.get("https://finnhub.io/api/v1/news",
                         params={"category": "general", "token": settings.FINNHUB_KEY},
                         timeout=10)
        r.raise_for_status()
        items = [{"headline": n.get("headline", ""), "source": n.get("source", ""),
                  "datetime": time.strftime("%Y-%m-%d", time.gmtime(n.get("datetime", 0)))}
                 for n in (r.json() or [])[:20] if n.get("headline")]
        return {"available": True, "items": items}
    except Exception as e:
        msg = re.sub(r"token=[^&\s'\"]*", "token=[REDACTED]", str(e))
        return {"available": False, "reason": msg[:120], "items": []}
