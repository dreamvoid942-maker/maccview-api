"""Goose Feather 1.6 scoring endpoint — Maccview's standalone Worker.

Flow: ALOD relay -> exact 192-vector -> own Worker /score -> 3-way rule.

No desk session, Origin proxy or signed envelope. No fabricated probability:
missing bars are "no data", an unreachable Worker is "model offline". The
probability is always returned with its CT and the resulting action.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from ..config import settings
from ..routers.auth import require_session
from ..services.feather import (MIN_BARS, SOURCES, FeatureError, feature_vector,
                                fetch_bars)
from ..services.model_gateway import MODELS, ModelGateway, decision

router = APIRouter(prefix="/feather", tags=["feather"])


class ScoreRequest(BaseModel):
    symbol: str
    src: str = "auto"
    tf: str = "1h"
    n: int = 1600
    model: str | None = None
    ct: float | None = None
    # For parity tests only: score bars the caller already has.
    bars: list[list[Any]] | None = None


def _ct(value: float | None) -> float:
    ct = float(settings.LW_CT) if value is None else float(value)
    if not 0.50 <= ct <= 0.90:
        raise HTTPException(status_code=400, detail="ct must be between 0.50 and 0.90")
    return ct


@router.get("/health")
def health():
    """Config status only. No secrets, no URLs with credentials."""
    base = getattr(settings, "MACCVIEW_MODEL_URL", "") or ""
    return {
        "ok": True,
        "models": list(MODELS),
        "default_model": getattr(settings, "LW_MODEL", "summit"),
        "ct": float(getattr(settings, "LW_CT", 0.60)),
        "lookback": 256,
        "min_bars": MIN_BARS,
        "features": 192,
        "gateway_configured": bool(base),
        "alod_configured": bool(getattr(settings, "ALOD_RELAY_URL", "")),
        "alod_sources": list(SOURCES),
    }


@router.post("/score")
def score(req: ScoreRequest, authorization: str | None = Header(default=None)):
    require_session(authorization)

    ct = _ct(req.ct)
    model = (req.model or getattr(settings, "LW_MODEL", "summit") or "summit").strip().lower()
    if model not in MODELS:
        raise HTTPException(status_code=400, detail="model must be one of %s" % (list(MODELS),))

    try:
        bars = req.bars or fetch_bars(
            getattr(settings, "ALOD_RELAY_URL", ""), req.src, req.symbol,
            req.tf, req.n)
        vector = feature_vector(bars)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="no data: %s" % exc)

    gw = ModelGateway(getattr(settings, "MACCVIEW_MODEL_URL", ""), model=model)
    try:
        result = gw.score(vector, model)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="model offline: %s" % exc)

    p = float(result["p"])
    return {
        "ok": True,
        "live": True,
        "source": "goose-feather-1.6",
        "symbol": req.symbol,
        "src": req.src,
        "tf": req.tf,
        "model": result["model"],
        "p": p,
        "ct": ct,
        "action": decision(p, ct),
        "conviction": result.get("conviction"),
        "gateway_action": result.get("action"),
        "compare": result.get("all") or {},
        "bars_used": len(bars) - 1,
    }
