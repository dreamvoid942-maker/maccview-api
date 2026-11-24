import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from .config import Config


def generate_sample_data(path: str = 'sample_data.csv', n: int = 1000) -> pd.DataFrame:
    """
    Generate synthetic OHLCV data with realistic regime dynamics.
    Fully asset-agnostic: price starts at 100.0, volatility expressed in log-return σ.
    No assumptions about asset type, timeframe, or price scale.
    """
    print(f"Generating {n} synthetic candles (asset-agnostic)...")
    timestamps, opens, highs, lows, closes, volumes = [], [], [], [], [], []
    current_time = datetime(2024, 1, 1)
    price = 100.0                   # Neutral starting price
    regime = 'neutral'
    regime_vol, regime_trend = 0.008, 0.0001

    for i in range(n):
        if np.random.random() < 0.015:
            regime = np.random.choice(['neutral', 'bull', 'bear', 'range', 'high_vol'])
            regime_trend = {
                'bull': 0.0003, 'bear': -0.0003, 'range': 0.0,
                'neutral': 0.0001, 'high_vol': 0.0001
            }[regime]
            regime_vol = {
                'bull': 0.006, 'bear': 0.006, 'range': 0.004,
                'neutral': 0.008, 'high_vol': 0.020
            }[regime]

        o = price
        intrabar_vol = regime_vol * np.random.uniform(0.5, 1.5)
        c = o * (1 + np.random.normal(regime_trend, intrabar_vol))
        hl_range = abs(o - c) + abs(np.random.normal(0, intrabar_vol * o))

        if c > o:
            h = c + np.random.exponential(hl_range * 0.3)
            l = o - np.random.exponential(hl_range * 0.2)
        else:
            h = o + np.random.exponential(hl_range * 0.2)
            l = c - np.random.exponential(hl_range * 0.3)

        h, l = max(h, o, c), min(l, o, c)

        if np.random.random() < 0.001:
            shock = np.random.choice([-1, 1]) * np.random.uniform(0.03, 0.12)
            c *= (1 + shock)
            h, l = max(h, c), min(l, c)

        # Volume correlates with price move magnitude (universal pattern)
        v = int(1e6 * (1 + abs(np.log(max(c / o, 1e-10))) * 50) * np.random.uniform(0.5, 1.5))

        timestamps.append(current_time)
        opens.append(o); highs.append(h); lows.append(l)
        closes.append(c); volumes.append(v)
        price = c
        current_time += timedelta(minutes=1)

    df = pd.DataFrame({
        'timestamp': timestamps, 'open': opens, 'high': highs,
        'low': lows, 'close': closes, 'volume': volumes
    })
    df.to_csv(path, index=False)
    print(f"OK Saved {len(df):,} candles | Range: {df['low'].min():.4f} - {df['high'].max():.4f}")
    return df


class DataNormalizer:
    """
    Min-max normalizer fitted per dataset. Asset-agnostic.
    The normalizer adapts to any price scale (forex pip, BTC thousands, etc.)
    """
    def __init__(self): self.stats = {}

    def fit(self, ohlcv: np.ndarray):
        self.stats = {
            'price_min': ohlcv[:, :4].min(), 'price_max': ohlcv[:, :4].max(),
            'vol_min': ohlcv[:, 4].min(), 'vol_max': ohlcv[:, 4].max(),
        }

    def normalize_ohlcv(self, ohlcv: np.ndarray) -> np.ndarray:
        n = ohlcv.copy()
        pr = self.stats['price_max'] - self.stats['price_min'] + 1e-10
        vr = self.stats['vol_max'] - self.stats['vol_min'] + 1e-10
        n[:, :4] = (ohlcv[:, :4] - self.stats['price_min']) / pr
        n[:, 4] = (ohlcv[:, 4] - self.stats['vol_min']) / vr
        return n

    def denormalize_ohlcv(self, normalized: np.ndarray) -> np.ndarray:
        o = normalized.copy()
        pr = self.stats['price_max'] - self.stats['price_min']
        vr = self.stats['vol_max'] - self.stats['vol_min']
        o[:, :4] = normalized[:, :4] * pr + self.stats['price_min']
        o[:, 4] = normalized[:, 4] * vr + self.stats['vol_min']
        return o

    def denormalize_tensor(self, t):
        r = t.clone()
        pr = self.stats['price_max'] - self.stats['price_min']
        vr = self.stats['vol_max'] - self.stats['vol_min']
        r[..., :4] = t[..., :4] * pr + self.stats['price_min']
        r[..., 4] = t[..., 4] * vr + self.stats['vol_min']
        return r

    def save(self, path: str): np.save(path, self.stats)
    def load(self, path: str): self.stats = np.load(path, allow_pickle=True).item()


class FeatureEngine:
    """
    48 features organized into semantic groups.
    IQR normalization ensures asset-agnosticism: features describe
    relative statistics, not absolute price levels.

    Feature groups:
      1. Raw OHLCV (5) -- used only as inputs to relative computations
      2. Return & bar structure (8) -- body, wick, log-return
      3. ATR & volatility (7) -- realized vol, vol-of-vol, ratio
      4. Moving averages & cross signals (6) -- price deviation from MA
      5. Momentum ROC multi-window (5) -- 3/5/10/20 period returns
      6. Bollinger Band features (2) -- %B and bandwidth
      7. RSI (2) -- fast and slow
      8. Swing high/low distance (4) -- support/resistance proximity
      9. Volume features (4) -- relative volume, trend
     10. Lag & autocorrelation proxy (4) -- lag-1, lag-2, autocorr, signed-mom
     11. Compound features (1) -- micro-vol normalized by ATR
    """
    def __init__(self, config: Config): self.config = config

    def compute_features(self, ohlcv: np.ndarray) -> np.ndarray:
        O, H, L, C, V = ohlcv[:, 0], ohlcv[:, 1], ohlcv[:, 2], ohlcv[:, 3], ohlcv[:, 4]
        T = len(C)

        # Pandas series for efficient rolling (critical at large scale)
        C_s, V_s, H_s, L_s = pd.Series(C), pd.Series(V), pd.Series(H), pd.Series(L)

        # -- Returns & bar structure ------------------------------------------
        log_ret = np.zeros(T)
        log_ret[1:] = np.log(np.clip(C[1:] / C[:-1], 1e-10, None))
        body = C - O
        rng = H - L
        upper_wick = H - np.maximum(O, C)
        lower_wick = np.minimum(O, C) - L
        body_pct = body / (rng + 1e-10)       # Body position in bar [-1, 1]
        upper_pct = upper_wick / (rng + 1e-10) # Upper wick fraction
        lower_pct = lower_wick / (rng + 1e-10) # Lower wick fraction

        # -- ATR & volatility -------------------------------------------------
        rng_s = pd.Series(rng)
        atr5  = rng_s.rolling(5, min_periods=1).mean().values
        atr14 = rng_s.rolling(14, min_periods=1).mean().values
        atr_ratio = atr5 / (atr14 + 1e-10)         # Short vs long ATR ratio

        lr_s = pd.Series(log_ret)
        vol5  = lr_s.rolling(5, min_periods=1).std().fillna(0).values
        vol14 = lr_s.rolling(14, min_periods=1).std().fillna(0).values
        vol50 = lr_s.rolling(50, min_periods=1).std().fillna(0).values
        vol_of_vol = pd.Series(vol14).rolling(14, min_periods=1).std().fillna(0).values
        vol_ratio  = vol5 / (vol50 + 1e-10)         # Vol clustering indicator

        # -- Moving averages & cross signals ----------------------------------
        sma5   = C_s.rolling(5, min_periods=1).mean().values
        sma14  = C_s.rolling(14, min_periods=1).mean().values
        sma50  = C_s.rolling(50, min_periods=1).mean().values
        sma200 = C_s.rolling(200, min_periods=1).mean().values
        pvs5   = (C - sma5)   / (sma5   + 1e-10)   # % deviation from fast MA
        pvs14  = (C - sma14)  / (sma14  + 1e-10)
        pvs50  = (C - sma50)  / (sma50  + 1e-10)
        pvs200 = (C - sma200) / (sma200 + 1e-10)
        cross_fast = (sma5  - sma14) / (sma14 + 1e-10) # Fast/slow cross signal
        cross_slow = (sma14 - sma50) / (sma50 + 1e-10) # Medium/long cross

        # -- Momentum ROC multi-window -----------------------------------------
        def log_roc(shift):
            out = np.zeros(T)
            out[shift:] = np.log(np.clip(C[shift:] / C[:-shift], 1e-10, None))
            return out

        roc3  = log_roc(3); roc5 = log_roc(5)
        roc10 = log_roc(10); roc20 = log_roc(20)
        momentum10 = lr_s.rolling(10, min_periods=1).sum().values

        # -- Bollinger Bands ---------------------------------------------------
        sma20 = C_s.rolling(20, min_periods=1).mean().values
        std20 = C_s.rolling(20, min_periods=1).std().fillna(0).values
        bb_upper = sma20 + 2 * std20
        bb_lower = sma20 - 2 * std20
        bb_pct   = (C - bb_lower) / (bb_upper - bb_lower + 1e-10)
        bb_width = (bb_upper - bb_lower) / (sma20 + 1e-10)

        # -- RSI ---------------------------------------------------------------
        gains  = np.maximum(log_ret, 0)
        losses = np.maximum(-log_ret, 0)
        ag5  = pd.Series(gains).rolling(5, min_periods=1).mean().values
        al5  = pd.Series(losses).rolling(5, min_periods=1).mean().values
        ag14 = pd.Series(gains).rolling(14, min_periods=1).mean().values
        al14 = pd.Series(losses).rolling(14, min_periods=1).mean().values
        rsi5  = 100 - 100 / (1 + ag5  / (al5  + 1e-10))
        rsi14 = 100 - 100 / (1 + ag14 / (al14 + 1e-10))

        # -- Swing high/low distance -------------------------------------------
        swing_h = H_s.rolling(14, min_periods=1).max().values
        swing_l = L_s.rolling(14, min_periods=1).min().values
        dist_to_high = (swing_h - C) / (swing_h + 1e-10)
        dist_to_low  = (C - swing_l) / (swing_l + 1e-10)

        # -- Volume features ---------------------------------------------------
        vol_ma5  = V_s.rolling(5, min_periods=1).mean().values
        vol_ma14 = V_s.rolling(14, min_periods=1).mean().values
        vol_ratio_v = V / (vol_ma14 + 1e-10)
        vol_trend   = (vol_ma5 - vol_ma14) / (vol_ma14 + 1e-10)

        # -- Lag & autocorrelation proxy ---------------------------------------
        lag1_ret   = np.concatenate([[0], log_ret[:-1]])
        lag2_ret   = np.concatenate([[0, 0], log_ret[:-2]])
        autocorr   = log_ret * lag1_ret          # Lag-1 autocorrelation (unnormalized)
        signed_mom = np.sign(roc5) * np.sqrt(np.abs(roc5))  # Signed momentum

        # -- Stack 48 features -------------------------------------------------
        features = np.stack([
            # Raw OHLCV (5)
            O, H, L, C, V,
            # Return & bar structure (8)
            log_ret, body, rng, upper_wick, lower_wick,
            body_pct, upper_pct, lower_pct,
            # ATR & volatility (7)
            atr14, atr5, atr_ratio, vol14, vol5, vol_of_vol, vol_ratio,
            # Vol level (1)
            vol50,
            # MA & cross signals (6)
            pvs5, pvs14, pvs50, pvs200, cross_fast, cross_slow,
            # Momentum ROC (5)
            roc3, roc5, roc10, roc20, momentum10,
            # Bollinger (2)
            bb_pct, bb_width,
            # RSI (2)
            rsi14, rsi5,
            # Swing distance (4)
            swing_h, swing_l, dist_to_high, dist_to_low,
            # Volume (4)
            vol_ma14, vol_ratio_v, vol_ma5, vol_trend,
            # Lag & autocorr (4)
            lag1_ret, lag2_ret, autocorr, signed_mom,
        ], axis=1)
        # Total: 5+8+7+1+6+5+2+2+4+4+4 = 48 OK

        # Robust IQR normalization -- makes all features scale-invariant
        # This is the key to asset-agnosticism: features describe statistics
        # relative to their own distribution, not absolute values
        med = np.median(features, axis=0, keepdims=True)
        q75 = np.percentile(features, 75, axis=0, keepdims=True)
        q25 = np.percentile(features, 25, axis=0, keepdims=True)
        iqr = np.where(q75 - q25 > 0, q75 - q25, 1.0)
        features = np.clip((features - med) / iqr, -5, 5)

        if features.shape[1] < self.config.FEATURE_DIM:
            pad = self.config.FEATURE_DIM - features.shape[1]
            features = np.pad(features, ((0, 0), (0, pad)))

        return features[:, :self.config.FEATURE_DIM].astype(np.float32)
