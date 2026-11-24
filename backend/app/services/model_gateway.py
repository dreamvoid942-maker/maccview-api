"""Maccview's own Goose Feather 1.6 scorer (standalone Worker).

No Supabase, no Origin header, no X-LW-* envelope. The Worker holds the model
JSONs and walks the trees; this service only sends the 192-float vector.

    POST {MACCVIEW_MODEL_URL}/score  {"features":[...], "model":"summit"}
    GET  {MACCVIEW_MODEL_URL}/health
"""
from __future__ import annotations

from typing import Any, Sequence

MODELS = ("summit", "kampa", "willow", "base", "all")


class GatewayError(RuntimeError):
    pass


def decision(p: float, ct: float) -> str:
    """3-way rule. Always show CT with the probability."""
    if p >= ct:
        return "LONG"
    if p <= 1.0 - ct:
        return "SHORT"
    return "STAND ASIDE"


class ModelGateway:
    def __init__(self, base_url: str, model: str = "summit", timeout: float = 20.0):
        self.base = (base_url or "").rstrip("/")
        if self.base and not self.base.startswith("https://"):
            raise GatewayError("model gateway must be HTTPS")
        self.model = model if model in MODELS else "summit"
        self.timeout = timeout

    def health(self) -> dict:
        import requests
        if not self.base:
            raise GatewayError("model gateway not configured")
        r = requests.get(self.base + "/health", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def score(self, features: Sequence[float], model: str | None = None) -> dict:
        import requests
        if not self.base:
            raise GatewayError("model gateway not configured")
        if len(features) != 192:
            raise GatewayError("feature vector must have 192 values")
        want = model or self.model
        if want not in MODELS:
            raise GatewayError("unknown model: %s" % want)
        r = requests.post(self.base + "/score",
                          json={"features": list(features), "model": want},
                          timeout=self.timeout)
        try:
            d = r.json()
        except ValueError:
            d = {}
        if not r.ok:
            raise GatewayError(str(d.get("error") or "gateway %d" % r.status_code))
        if not isinstance(d.get("p"), (int, float)):
            raise GatewayError("gateway: malformed response")
        return {"p": float(d["p"]), "action": d.get("action"),
                "conviction": d.get("conviction"), "model": want,
                "all": {k: d[k] for k in ("p_summit", "p_kampa", "p_willow", "p_base")
                        if k in d}}


def compare(features: Sequence[float], base_url: str, timeout: float = 20.0) -> dict[str, float]:
    """Score the same vector with all four models in one call."""
    return ModelGateway(base_url, "all", timeout).score(features)["all"]
