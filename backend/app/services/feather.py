"""ALOD bars -> the exact 192-float Goose Feather 1.6 feature vector.

Nothing here invents features. The engine is the vendored ocln FeatureEngine
(identical compute_features body to Lightworks) and window_stats is copied
verbatim from feather_server.py:

    feats = ENGINE.compute_features(ohlcv)        # (T, 48)
    X     = window_stats(feats[-256:], 256)        # (1, 192), float32

Bars must be oldest-first UTC with columns [time, o, h, l, c, v], from the
ALOD relay. The last bar is forming and is always dropped.
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Sequence

import numpy as np

from ..ml.ocln.config import Config
from ..ml.ocln.features import FeatureEngine

LOOKBACK = 256
MIN_BARS = LOOKBACK + 260          # 516 — matches /health on the reference server
FEATURE_DIM = 48
VECTOR_DIM = FEATURE_DIM * 4       # last | mean | std | slope

ENGINE = FeatureEngine(Config())

# Sources implemented by alod-relay.js. No open proxy: each one builds its
# upstream URL from a fixed template. twelvedata is deliberately not used:
# the live Worker has no TWELVEDATA_KEY secret.
SOURCES = ("yahoo", "kraken", "bybit", "okx", "coinbase", "kucoin",
           "cryptocom", "binance", "cnbc", "twelvedata")

# Verbatim from the desk's js/core/alod-feeds.js `this.map`.
DESK_MAP = {
    "XAU/USD": "GC=F", "XAG/USD": "SI=F",
    "US500": "^GSPC", "SPX": "^GSPC",
    "USTEC": "^NDX", "NDX": "^NDX",
    "US30": "^DJI", "DJI": "^DJI",
    "DE30": "^GDAXI", "DAX": "^GDAXI",
    "UK100": "^FTSE", "FTSE100": "^FTSE",
    "JP225": "^N225", "N225": "^N225",
    "HK50": "^HSI", "HSI": "^HSI",
    "EUR/USD": "EURUSD=X", "GBP/USD": "GBPUSD=X", "USD/JPY": "USDJPY=X",
    "AUD/USD": "AUDUSD=X", "USD/CAD": "USDCAD=X", "USD/CHF": "USDCHF=X",
    "EUR/JPY": "EURJPY=X", "GBP/JPY": "GBPJPY=X", "NZD/USD": "NZDUSD=X",
}

# Maccview's compact symbols -> the desk's slash form. Crypto is the exception:
# the desk sends crypto unchanged and NEVER applies the map to it.
COMPACT_MAP = {
    "XAUUSD": "XAU/USD", "XAGUSD": "XAG/USD",
    "EURUSD": "EUR/USD", "GBPUSD": "GBP/USD", "USDJPY": "USD/JPY",
    "AUDUSD": "AUD/USD", "USDCAD": "USD/CAD", "USDCHF": "USD/CHF",
    "EURJPY": "EUR/JPY", "GBPJPY": "GBP/JPY", "NZDUSD": "NZD/USD",
    "NAS100": "NDX", "US500": "US500", "US30": "US30",
    "DE30": "DE30", "UK100": "UK100", "JP225": "JP225", "HK50": "HK50",
    "SPX": "SPX", "DJI": "DJI", "DAX": "DAX", "FTSE100": "FTSE100",
    "N225": "N225", "HSI": "HSI", "USTEC": "USTEC",
}
CRYPTO_BASES = ("BTC", "ETH", "SOL", "XRP", "ADA", "DOGE", "LTC", "BNB",
                "AVAX", "DOT", "LINK", "MATIC")


class FeatureError(ValueError):
    """Bad bars or a non-finite feature vector. Never produce a score."""


def window_stats(feats: np.ndarray, L: int = LOOKBACK) -> np.ndarray:
    """Verbatim from tools/feather_server.py — do not change."""
    arr = feats[-L:]
    last = arr[-1]
    mean = arr.mean(0)
    std = arr.std(0)
    slope = (arr[-1] - arr[0]) / L
    return np.concatenate([last, mean, std, slope]).astype(np.float32)[None, :]


def matrix_from_bars(bars: Sequence[Sequence[Any]]) -> np.ndarray:
    """[time,o,h,l,c,v] rows -> float64 [o,h,l,c,v], oldest first, closed only."""
    if not bars:
        raise FeatureError("no bars")
    rows = []
    for b in bars:
        try:
            if len(b) < 6:
                raise ValueError("short row")
            row = [float(b[1]), float(b[2]), float(b[3]), float(b[4]), float(b[5])]
        except (TypeError, ValueError) as exc:
            raise FeatureError("malformed bar") from exc
        if not all(math.isfinite(x) for x in row):
            raise FeatureError("bars contain a non-finite value")
        if row[1] < row[2]:
            raise FeatureError("bar has high < low")
        rows.append(row)

    arr = np.asarray(rows, dtype=np.float64)
    if len(arr) < MIN_BARS:
        raise FeatureError("need %d bars, got %d" % (MIN_BARS, len(arr)))
    return arr[:-1]                      # last bar is still forming


def feature_vector(bars: Sequence[Sequence[Any]]) -> list[float]:
    """Return the 192 floats sent to /score. Raises on any non-finite value."""
    arr = matrix_from_bars(bars)
    feats = ENGINE.compute_features(arr)
    if not np.isfinite(feats).all():
        raise FeatureError("feature computation produced NaN")
    X = window_stats(feats, LOOKBACK)
    if X.shape != (1, VECTOR_DIM) or not np.isfinite(X).all():
        raise FeatureError("invalid feature window")
    return X[0].tolist()


def normalize_symbol(symbol: str) -> str:
    """Maccview symbol -> desk symbol, e.g. XAUUSD -> XAU/USD."""
    s = (symbol or "").strip().upper()
    if not s:
        raise FeatureError("symbol required")
    if "/" in s:                       # already desk form (XAU/USD, BTC/USD)
        return s
    if COMPACT_MAP.get(s):
        return COMPACT_MAP[s]
    for base in CRYPTO_BASES:          # BTCUSD -> BTC/USD, no map for crypto
        if s.startswith(base) and s.endswith(("USD", "USDT", "EUR", "GBP")):
            quote = "USDT" if s.endswith("USDT") else s[len(base):]
            return base + "/" + quote
    return s


def class_of(symbol: str) -> str:
    s = normalize_symbol(symbol)
    base = s.split("/")[0]
    if base in CRYPTO_BASES:
        return "crypto"
    if base in ("XAU", "XAG"):
        return "metal"
    if s in ("US500", "SPX", "USTEC", "NDX", "US30", "DJI", "DE30", "DAX",
             "UK100", "FTSE100", "JP225", "N225", "HK50", "HSI"):
        return "index"
    return "fx"


def resolve_symbol(symbol: str, src: str) -> str:
    """Exact desk rule: crypto / twelvedata / cnbc send as-is, others map."""
    s = normalize_symbol(symbol)
    if class_of(symbol) == "crypto" or src in ("twelvedata", "cnbc"):
        return s
    return DESK_MAP.get(s, s)


def source_chain(symbol: str, tf: str) -> tuple[str, ...]:
    """The desk's real source preference chain."""
    cls = class_of(symbol)
    if cls == "crypto":
        return ("binance", "kraken", "bybit")
    if tf in ("1min", "5min", "15min") and cls in ("index", "metal"):
        return ("cnbc", "yahoo")
    return ("yahoo",)


def _fetch_one(base_url: str, src: str, symbol: str, tf: str, n: int,
               timeout: float, client: Any) -> list[list[Any]]:
    resp = client.get(base_url + "/", params={
        "src": src, "symbol": symbol, "tf": tf,
        "n": max(MIN_BARS + 1, min(int(n), 5000)),
    }, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("ok"):
        raise FeatureError(str(data.get("error") or "ALOD relay error"))
    bars = data.get("bars") or []
    if not bars:
        raise FeatureError("ALOD returned no bars")
    return bars


def fetch_bars(base_url: str, src: str, symbol: str, tf: str = "1h",
               n: int = 1600, timeout: float = 20.0,
               session: Any = None) -> list[list[Any]]:
    """GET bars from the live ALOD relay, with the desk's source fallback chain.

    src="auto" (default for Maccview) picks the chain; an explicit src pins one.
    base_url is server-side config, never in the app bundle.
    """
    import requests  # imported lazily so feature-only tests need no HTTP stack

    if not symbol:
        raise FeatureError("symbol required")
    base = (base_url or "").rstrip("/")
    if not base.startswith("https://"):
        raise FeatureError("ALOD relay must be HTTPS")
    client = session or requests
    src = (src or "auto").strip().lower()
    chain = (src,) if src != "auto" else source_chain(symbol, tf)
    last: Exception | None = None
    for source in chain:
        if source not in SOURCES:
            raise FeatureError("unknown ALOD source: %s" % source)
        try:
            return _fetch_one(base, source, resolve_symbol(symbol, source),
                              tf, n, timeout, client)
        except Exception as exc:
            last = exc
    raise FeatureError("all ALOD sources failed: %s" % last)
