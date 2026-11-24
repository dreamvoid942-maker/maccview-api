"""Paystack payments — initialize / verify / webhook.

Trust model (money rules):
  * Credits move ONLY when Paystack itself confirms status == "success".
  * The webhook is authenticated by the `x-paystack-signature` header,
    an HMAC SHA512 of the RAW request body keyed by the secret key.
  * The amount/currency Paystack reports must match the amount we asked
    for on the stored payment row. A mismatch credits nothing.
  * Every crediting operation is idempotent on `reference`.

Without a secret key the router stays in demo mode: no live calls are
attempted, and responses say so explicitly (`demo: true`).
"""
import hashlib
import hmac
import json
import time
import uuid

import requests
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..config import settings
from ..database import get_db
from ..routers.auth import require_session

router = APIRouter(prefix="/payments", tags=["payments"])

PAYSTACK_API = "https://api.paystack.co"

PLANS = {
    "p20": {"credits": 20, "amount_kobo": 1000 * 100},
    "p100": {"credits": 100, "amount_kobo": 5000 * 100},
    "p300": {"credits": 300, "amount_kobo": 13500 * 100},
}

CURRENCY = "NGN"

# Payment channels shown on the Paystack checkout page. Bank transfer is the
# one people actually reach for in Nigeria (transfer from Opay/any banking
# app to the temporary account Paystack displays), and it needs no card.
# Paystack shows all enabled channels by default; we pin the list explicitly
# so the behaviour does not drift with account settings.
#   card          — Visa / Mastercard / Verve
#   bank_transfer — temporary account number, no card needed
#   ussd          — dial a code, works without data
#   qr            — scan with a banking app
CHANNELS = ["card", "bank_transfer", "ussd", "qr"]

# Paystack reports these on the transaction; anything else is a red flag.
SUCCESS = "success"


class InitIn(BaseModel):
    plan: str = "p20"
    email: str = "demo@maccview.app"


def _norm_email(email: str) -> str:
    return (email or "demo@maccview.app").strip().lower() or "demo@maccview.app"


def _sanitize(msg: str, limit: int = 200) -> str:
    import re

    s = str(msg or "")
    s = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", s)
    s = re.sub(r"apikey=[^&\s'\"]*", "apikey=[REDACTED]", s)
    s = re.sub(r"sk_live_[A-Za-z0-9]+", "sk_live_[REDACTED]", s)
    s = re.sub(r"sk_test_[A-Za-z0-9]+", "sk_test_[REDACTED]", s)
    return s[:limit]


def _key_mode() -> str:
    """Which Paystack mode the configured secret key belongs to."""
    key = settings.PAYSTACK_SECRET_KEY or ""
    if key.startswith("sk_live_"):
        return "live"
    if key.startswith("sk_test_"):
        return "test"
    return "demo" if not key else "unknown"


def _payer_email_of(data: dict, fallback: str) -> str:
    """Prefer the email Paystack actually charged over our stored one."""
    cust = data.get("customer") or {}
    got = (cust.get("email") or "").strip().lower()
    return got or fallback


def _callback_url(req: Request | None) -> str:
    """Where Paystack returns the browser after a completed checkout.

    Only used by the hosted-page path (inline library unavailable). The
    explicit CALLBACK_URL setting wins; otherwise derive it from the caller's
    Origin, which is the app's own webview. Returns "" when neither is known,
    and Paystack then falls back to the dashboard callback URL.
    """
    configured = (settings.CALLBACK_URL or "").strip()
    if configured:
        return configured

    origin = ""
    if req is not None:
        try:
            origin = (req.headers.get("origin") or "").strip()
        except Exception:
            origin = ""
        if not origin:
            try:
                referer = (req.headers.get("referer") or "").strip()
            except Exception:
                referer = ""
            if referer:
                from urllib.parse import urlsplit

                sp = urlsplit(referer)
                if sp.scheme and sp.netloc:
                    origin = f"{sp.scheme}://{sp.netloc}"

    if not origin or origin == "null":
        return ""
    return origin.rstrip("/") + "/"


def _mark_payment(reference: str, status: str, raw: dict | None, gap: str = "") -> None:
    """Persist the verification verdict + raw payload for audit."""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE payments SET status=?, verified_at=?, raw_response=?, amount_gap=?"
            " WHERE reference=?",
            (status, int(time.time()), json.dumps(raw or {}, separators=(",", ":"))[:8000], gap, reference),
        )
        conn.commit()
    except Exception:
        # Column may not exist on a legacy row layout — fall back to status only.
        try:
            conn.execute("UPDATE payments SET status=? WHERE reference=?", (status, reference))
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()


def _paystack_verify(reference: str) -> dict:
    """Server-side Paystack confirm. Raises RuntimeError on transport failure."""
    key = settings.PAYSTACK_SECRET_KEY
    if not key:
        raise RuntimeError("no paystack secret key configured")
    r = requests.get(
        f"{PAYSTACK_API}/transaction/verify/{reference}",
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
        timeout=20,
    )
    if not r.ok:
        raise RuntimeError(f"paystack verify HTTP {r.status_code}: {_sanitize(r.text)}")
    try:
        body = r.json()
    except ValueError as e:
        raise RuntimeError(f"paystack verify returned non-JSON: {_sanitize(r.text)}") from e
    if not isinstance(body, dict):
        raise RuntimeError("paystack verify returned unexpected payload shape")
    return body.get("data") or {}


def _amount_gap(data: dict, expected_kobo: int) -> str:
    """Empty string when the charged amount matches; else a human-readable reason."""
    try:
        paid = int(data.get("amount") or 0)
    except (TypeError, ValueError):
        return "paystack reported a non-numeric amount"
    cur = str(data.get("currency") or CURRENCY).upper()
    if cur != CURRENCY:
        return f"currency mismatch: charged {cur}, expected {CURRENCY}"
    if paid < expected_kobo:
        return f"underpaid: {paid} kobo < {expected_kobo} kobo expected"
    if paid > expected_kobo:
        # Overpayment is allowed through (the customer paid more than asked)
        # but is recorded so it is visible in the audit trail.
        return f"overpaid: {paid} kobo > {expected_kobo} kobo expected"
    return ""


def _credit(email: str, credits: int, reference: str, payer_email: str = "") -> int:
    """Credit once — idempotent on `reference`. Returns the new balance.

    Credits are only ever written for a reference that exists as a payment
    row AND for an account that already exists, so a forged webhook cannot
    mint credits or conjure a user out of nothing.
    """
    from ..database import move_credits

    email = _norm_email(email)
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM payments WHERE reference=?", (reference,)).fetchone()
        if row is None:
            # No purchase record => refuse. Report the current balance
            # without touching it, so the call stays side-effect free.
            bal = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
            return int(bal["credits"]) if bal else 0
        pay = dict(row)
        if pay.get("status") == "success":
            bal = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
            return int(bal["credits"]) if bal else 0

        # The buyer must have an account. Purchases never create one.
        owner = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
        if owner is None:
            raise KeyError(f"no account for {email}")

        balance = move_credits(conn, email, int(credits), f"purchase {reference}")
        conn.execute("UPDATE payments SET status='success' WHERE reference=?", (reference,))
        conn.commit()
        return balance
    finally:
        conn.close()


def _confirm_and_credit(reference: str, pay_row: dict) -> dict:
    """Verify with Paystack, then credit. Returns a status dict for the caller."""
    data = _paystack_verify(reference)
    status = str(data.get("status") or "unknown").lower()
    if status != SUCCESS:
        _mark_payment(reference, status, data)
        return {"status": status, "credits_added": 0}

    gap = _amount_gap(data, int(pay_row.get("amount_kobo") or 0))
    if gap and gap.startswith(("currency", "underpaid", "paystack reported")):
        # Do not credit a transaction that did not actually pay what we asked.
        _mark_payment(reference, "amount_mismatch", data, gap)
        return {"status": "amount_mismatch", "credits_added": 0, "detail": gap}

    credits = _credit(
        pay_row.get("email") or "", int(pay_row.get("credits") or 0),
        reference, payer_email=_payer_email_of(data, pay_row.get("email") or ""),
    )
    _mark_payment(reference, "success", data, gap)
    return {"status": "success", "credits_added": int(pay_row.get("credits") or 0), "credits": credits}


@router.post("/initialize")
def initialize(body: InitIn, request: Request, authorization: str | None = Header(default=None)):
    # The buyer is whoever holds the session. A caller cannot pay into
    # somebody else's account by passing their email.
    sess = require_session(authorization)
    email = sess["email"]
    plan_key = body.plan if body.plan in PLANS else "p20"
    plan = PLANS[plan_key]
    reference = f"maccview-{uuid.uuid4().hex[:12]}"

    conn = get_db()
    try:
        owner = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
        if owner is None:
            raise HTTPException(status_code=404, detail="account not found")
        conn.execute(
            "INSERT INTO payments(reference,email,plan,amount_kobo,credits,status,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (reference, email, plan_key, plan["amount_kobo"], plan["credits"], "pending", int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()

    if not settings.PAYSTACK_SECRET_KEY:
        return {"reference": reference,
                "authorization_url": f"https://checkout.paystack.com/demo/{reference}",
                "channels": CHANNELS,
                "plan": plan_key, **plan, "demo": True, "mode": "demo"}

    try:
        payload = {"email": email, "amount": plan["amount_kobo"],
                   "currency": CURRENCY, "reference": reference,
                   "channels": CHANNELS}
        # Return the browser to the app after checkout. Only matters on the
        # hosted-page path, but harmless (and useful) on the inline one too.
        cb = _callback_url(request)
        if cb:
            payload["callback_url"] = cb
        r = requests.post(
            f"{PAYSTACK_API}/transaction/initialize",
            headers={"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                     "Accept": "application/json",
                     "Content-Type": "application/json"},
            json=payload,
            timeout=20,
        )
    except requests.RequestException as e:
        msg = f"paystack unreachable: {_sanitize(str(e))}"
        _mark_payment(reference, "init_failed", None, msg)
        return JSONResponse(status_code=502, content={
            "reference": reference, "error": "paystack_unreachable",
            "detail": msg, "plan": plan_key, "mode": _key_mode()})

    if not r.ok:
        msg = f"paystack initialize HTTP {r.status_code}: {_sanitize(r.text)}"
        _mark_payment(reference, "init_failed", None, msg)
        return JSONResponse(status_code=502, content={
            "reference": reference, "error": "paystack_rejected",
            "detail": msg, "plan": plan_key, "mode": _key_mode()})

    try:
        body_json = r.json()
    except ValueError:
        msg = f"paystack initialize returned non-JSON: {_sanitize(r.text)}"
        _mark_payment(reference, "init_failed", None, msg)
        return JSONResponse(status_code=502, content={
            "reference": reference, "error": "paystack_bad_response",
            "detail": msg, "plan": plan_key, "mode": _key_mode()})

    data = (body_json or {}).get("data") or {}
    url = data.get("authorization_url")
    if not url:
        msg = "paystack initialize returned no authorization_url"
        _mark_payment(reference, "init_failed", body_json, msg)
        return JSONResponse(status_code=502, content={
            "reference": reference, "error": "no_authorization_url",
            "detail": msg, "plan": plan_key, "mode": _key_mode()})

    if data.get("reference") and data["reference"] != reference:
        # Paystack should echo our reference back; a different one means we
        # cannot reliably match the webhook to this row.
        msg = f"reference mismatch: sent {reference}, got {data['reference']}"
        _mark_payment(reference, "init_failed", body_json, msg)
        return JSONResponse(status_code=502, content={
            "reference": reference, "error": "reference_mismatch",
            "detail": msg, "plan": plan_key, "mode": _key_mode()})

    return {"reference": reference, "authorization_url": url,
            "access_code": data.get("access_code", ""),
            "channels": CHANNELS,
            "plan": plan_key, **plan, "mode": _key_mode(), "demo": False}


@router.get("/verify/{reference}")
def verify(reference: str):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM payments WHERE reference=?", (reference,)).fetchone()
    finally:
        conn.close()

    if row is None:
        # Unknown ref credits nothing — never free credits.
        out = {"reference": reference, "status": "unknown", "credits_added": 0}
        if not settings.PAYSTACK_SECRET_KEY:
            out["demo"] = True
        return out

    d = dict(row)
    if d.get("status") == "success":
        conn2 = get_db()
        try:
            bal = conn2.execute("SELECT credits FROM users WHERE email=?", (d["email"],)).fetchone()
            credits = int(bal["credits"]) if bal else 0
        finally:
            conn2.close()
        # Idempotent repeat verify: already credited, so added = 0.
        return {"reference": reference, "status": "success", "credits_added": 0, "credits": credits}

    if not settings.PAYSTACK_SECRET_KEY:
        # Demo mode: no live key, so no real money can have moved either way.
        credits = _credit(d["email"], d["credits"], reference)
        return {"reference": reference, "status": "success",
                "credits_added": d["credits"], "credits": credits, "demo": True, "mode": "demo"}

    try:
        res = _confirm_and_credit(reference, d)
    except Exception as e:
        return {"reference": reference, "status": "error", "credits_added": 0,
                "detail": _sanitize(str(e))}
    return {"reference": reference, "mode": _key_mode(), **res}


def _valid_signature(raw: bytes, signature: str) -> bool:
    """HMAC SHA512 of the RAW body keyed by the secret key."""
    key = settings.PAYSTACK_SECRET_KEY
    if not key or not signature:
        return False
    expected = hmac.new(key.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature.strip().lower())


@router.post("/webhook")
async def webhook(req: Request):
    raw = await req.body()
    signature = req.headers.get("x-paystack-signature", "")

    if not settings.PAYSTACK_SECRET_KEY:
        # Nothing to authenticate against; accept the ping and do nothing.
        return {"ok": True, "demo": True}

    if not _valid_signature(raw, signature):
        # Forged or mis-signed: reject loudly so Paystack records a failure
        # and retries a genuine one, and so forged hooks never reach _credit.
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid signature"})

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return {"ok": True}

    if not isinstance(payload, dict):
        return {"ok": True}

    event = payload.get("event", "")
    data = payload.get("data") or {}
    if event != "charge.success" or not isinstance(data, dict):
        return {"ok": True}

    ref = data.get("reference", "")
    if not ref:
        return {"ok": True}

    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM payments WHERE reference=?", (ref,)).fetchone()
    finally:
        conn.close()

    if row is None:
        # Signature is valid but we never issued this reference. Log and stop.
        return {"ok": True, "ignored": "unknown reference"}

    if dict(row).get("status") == "success":
        return {"ok": True, "ignored": "already credited"}

    # Signature proves the payload came from Paystack, but we still re-confirm
    # server-side so credits follow Paystack's own transaction state, not the
    # webhook body alone.
    try:
        result = _confirm_and_credit(ref, dict(row))
    except Exception as e:
        # Returning 200 stops Paystack retrying a config error forever; the
        # failure is recorded on the payment row and reachable via /verify.
        _mark_payment(ref, dict(row).get("status") or "pending", None, _sanitize(str(e)))
        return {"ok": True, "verify_failed": _sanitize(str(e))}

    return {"ok": True, **result}
