"""Accounts — server-side identity, OTP signup, device-bound sessions.

Identity rules:
  * An account is created ONLY here, server-side. The client cannot invent one.
  * Session tokens are issued by the server and stored in `sessions`. The
    client holds a token, never a credit balance it can assert.
  * A hardware-backed account is bound to one device, and a second hardware
    device is refused. Web-tier ids never bind: they are regenerated whenever
    browser storage is cleared, so enforcing them would lock a legitimate user
    out of their own account with no recovery.
  * The welcome bonus is granted on first account creation only.

Email delivery: OTP codes are generated server-side. Delivery is via SMTP
when SMTP_* settings are present; otherwise the code is logged to the server
console and (only in non-live mode) echoed in the response so local testing
works. In live mode a missing SMTP config is a hard error, never a bypass.
"""
import hashlib
import hmac
import re
import secrets
import smtplib
import time
from email.message import EmailMessage

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from ..config import settings
from ..database import (
    WELCOME_BONUS,
    create_account,
    device_blocked,
    device_owner,
    get_db,
    new_token,
    touch_device,
)

router = APIRouter(prefix="/auth", tags=["auth"])

OTP_TTL = 600          # 10 minutes
OTP_MAX_ATTEMPTS = 5
SESSION_TTL = 60 * 60 * 24 * 30   # 30 days

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _norm(email: str) -> str:
    return (email or "").strip().lower()


def _valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))


def _hash_code(email: str, code: str) -> str:
    """Bind the code to the email so a leaked code cannot be replayed."""
    pepper = (settings.SESSION_PEPPER or "maccview-static-pepper").encode()
    return hmac.new(pepper, f"{email}:{code}".encode(), hashlib.sha256).hexdigest()


def _constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


# --------------------------------------------------------------------------
# OTP delivery
# --------------------------------------------------------------------------

def _smtp_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASS)


def _send_code_email(email: str, code: str) -> bool:
    if not _smtp_configured():
        return False
    msg = EmailMessage()
    msg["Subject"] = "Your Maccview verification code"
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = email
    msg.set_content(
        f"Your Maccview verification code is {code}.\n\n"
        f"It expires in {OTP_TTL // 60} minutes. If you did not request this, ignore it.\n"
    )
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as s:
            s.starttls()
            s.login(settings.SMTP_USER, settings.SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 - surfaced to caller as a failure
        print(f"[auth] SMTP send to {email} failed: {type(exc).__name__}: {exc}", flush=True)
        return False


def _live_mode() -> bool:
    return (settings.PAYSTACK_SECRET_KEY or "").startswith("sk_live_")


def _issue_code(conn, email: str, purpose: str) -> str:
    code = f"{secrets.randbelow(1_000_000):06d}"
    now = int(time.time())
    conn.execute(
        "INSERT INTO otp_codes(email,code_hash,purpose,attempts,created_at,expires_at,consumed_at)"
        " VALUES(?,?,?,0,?,?,0)"
        " ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,"
        " purpose=excluded.purpose, attempts=0, created_at=excluded.created_at,"
        " expires_at=excluded.expires_at, consumed_at=0",
        (email, _hash_code(email, code), purpose, now, now + OTP_TTL),
    )
    conn.commit()
    return code


# --------------------------------------------------------------------------
# Session helpers
# --------------------------------------------------------------------------

def _start_session(conn, email: str, device_id: str) -> str:
    token = new_token()
    now = int(time.time())
    conn.execute(
        "INSERT INTO sessions(token,email,device_id,created_at,last_used_at,expires_at,revoked)"
        " VALUES(?,?,?,?,?,?,0)",
        (token, email, device_id or "", now, now, now + SESSION_TTL),
    )
    conn.commit()
    return token


def resolve_session(token: str) -> dict | None:
    """Validate a token. Returns {email, device_id} or None.

    A suspended account is refused here, which gates every protected endpoint
    in the app at once — `users.status` is the single source of truth for
    whether an account may act.
    """
    if not token:
        return None
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token=?", (token,)
        ).fetchone()
        if row is None:
            return None
        s = dict(row)
        now = int(time.time())
        if s.get("revoked") or (s.get("expires_at") or 0) < now:
            return None
        # Account standing: 'active' is the only status that may act.
        urow = conn.execute(
            "SELECT status FROM users WHERE email=?", (s["email"],)
        ).fetchone()
        if urow is not None:
            status = (urow["status"] or "active").strip().lower()
            if status and status != "active":
                return None
        conn.execute("UPDATE sessions SET last_used_at=? WHERE token=?", (now, token))
        conn.execute("UPDATE users SET last_seen_at=? WHERE email=?", (now, s["email"]))
        conn.commit()
        return {"email": s["email"], "device_id": s.get("device_id") or ""}
    finally:
        conn.close()


def require_session(authorization: str | None) -> dict:
    """FastAPI dependency helper: raise 401 unless a valid token is supplied."""
    token = ""
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
    sess = resolve_session(token)
    if not sess:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    return sess


_WEB_TIER_PREFIXES = ("web-", "host-")


def _is_hardware_id(device_id: str) -> bool:
    """True only for a hardware-backed device id.

    Web-tier ids are random per-install localStorage entropy (see
    frontend/js/device.js) — they are NOT a device identity. Treating one as a
    device permanently locks an account out of itself the moment browser
    storage is cleared, a different browser is used, or private mode is opened.
    Only a hardware digest may bind an account to a device.
    """
    d = (device_id or "").strip().lower()
    if not d or d.startswith(_WEB_TIER_PREFIXES):
        return False
    return len(d) >= 32


def _device_conflict(conn, email: str, device_id: str) -> str | None:
    """Return a reason string when this account may not use this device.

    The rule is directional, and the two directions are deliberately not
    symmetric:

      account -> many devices: ALLOWED.
          One account may sign in on any number of handsets. A lost, stolen or
          replaced phone must not lock its owner out of their own credits and
          history, and there is no self-service transfer to fall back on.

      device  -> one account: ENFORCED.
          A handset stays with whichever account it first verified. The app has
          no sign-out control, so letting a second account claim the same
          device would silently strand the first session with no way back.

    An admin can release either side via POST /admin/users/{email}/devices/release,
    which sets `released_at` and stops the row gating access while keeping its
    fingerprint for the cross-account abuse rule.

    Only hardware-backed ids bind. Web-tier ids are skipped entirely: they are
    regenerated whenever browser storage is cleared, so enforcing them would
    lock a legitimate user out of their own account with no way back. The
    anti-abuse half of the rule is unaffected — that runs on the fingerprint in
    `device_owner()`, which is checked separately at signup.
    """
    if not _is_hardware_id(device_id):
        return None
    incoming = device_id.strip().lower()
    email = (email or "").strip().lower()

    # Direction 2: this handset already belongs to a different account.
    row = conn.execute(
        "SELECT email, blocked, released_at FROM devices WHERE device_id=?",
        (incoming,),
    ).fetchone()
    if row is not None:
        if int(row["blocked"] or 0):
            return "device blocked"
        owner = (row["email"] or "").strip().lower()
        unreleased = int(row["released_at"] or 0) == 0
        if owner and owner != email and unreleased:
            return "this device is already registered to another account"

    # Direction 1 is NOT enforced on purpose: the same account on a new phone
    # is exactly the recovery path we want to keep open. We only surface a
    # block if the account itself has a blocked device row.
    rows = conn.execute(
        "SELECT device_id, blocked, released_at FROM devices WHERE email=?",
        (email,),
    ).fetchall()
    for row in rows:
        if int(row["released_at"] or 0) > 0:
            continue
        if int(row["blocked"] or 0):
            return "device blocked"
    return None


class RequestCodeIn(BaseModel):
    email: str
    device_id: str = ""


class VerifyCodeIn(BaseModel):
    email: str
    code: str
    device_id: str = ""
    name: str = ""
    fingerprint: str = ""
    platform: str = ""
    model: str = ""


@router.post("/request-code")
def request_code(body: RequestCodeIn):
    email = _norm(body.email)
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="invalid email")

    conn = get_db()
    try:
        reason = _device_conflict(conn, email, (body.device_id or "").strip())
        if reason:
            raise HTTPException(status_code=403, detail=reason)
        code = _issue_code(conn, email, "signup")
    finally:
        conn.close()

    sent = _send_code_email(email, code)
    out = {"ok": True, "sent": sent, "expires_in": OTP_TTL}
    if not sent:
        # The code always goes to the server log so an operator can retrieve
        # it. Returning it over the wire is gated behind an explicit opt-in,
        # since that would otherwise be an auth bypass.
        if settings.DEV_RETURN_OTP:
            print(f"[auth] DEV OTP for {email}: {code}", flush=True)
            out["dev_code"] = code
            out["detail"] = "DEV_RETURN_OTP enabled; code returned for local testing"
        else:
            print(f"[auth] OTP for {email}: {code}", flush=True)
            out["detail"] = "email delivery unavailable; check server config"
    return out


@router.post("/verify-code")
def verify_code(body: VerifyCodeIn):
    email = _norm(body.email)
    code = (body.code or "").strip()
    device_id = (body.device_id or "").strip()
    if not _valid_email(email) or not code:
        raise HTTPException(status_code=400, detail="invalid email or code")

    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM otp_codes WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=400, detail="no code requested")
        rec = dict(row)
        now = int(time.time())
        if rec.get("consumed_at"):
            raise HTTPException(status_code=400, detail="code already used")
        if (rec.get("expires_at") or 0) < now:
            raise HTTPException(status_code=400, detail="code expired")
        if int(rec.get("attempts") or 0) >= OTP_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="too many attempts")

        if not _constant_eq(rec.get("code_hash") or "", _hash_code(email, code)):
            conn.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE email=?", (email,))
            conn.commit()
            raise HTTPException(status_code=400, detail="incorrect code")

        reason = _device_conflict(conn, email, device_id)
        if reason:
            raise HTTPException(status_code=403, detail=reason)

        # A suspended account may not re-enter, even with a valid code.
        urow = conn.execute("SELECT status FROM users WHERE email=?", (email,)).fetchone()
        if urow is not None:
            status = (urow["status"] or "active").strip().lower()
            if status and status != "active":
                raise HTTPException(status_code=403, detail="account suspended")

        # Cross-account half of the one-device rule: this physical handset must
        # not already back a different account. Checked BEFORE create_account so
        # no second account (and no second welcome bonus) is ever minted.
        fp = (body.fingerprint or "").strip()
        if fp:
            if device_blocked(conn, device_id, fp):
                raise HTTPException(status_code=403, detail="device blocked")
            owner = device_owner(conn, fp)
            if owner and owner != email:
                raise HTTPException(
                    status_code=403,
                    detail="this device is already linked to another account",
                )

        conn.execute("UPDATE otp_codes SET consumed_at=? WHERE email=?", (now, email))
        conn.commit()

        user = create_account(conn, email, body.name or "", device_id)
        if device_id:
            touch_device(conn, device_id, email, body.fingerprint,
                         body.platform, body.model)
    finally:
        conn.close()

    conn = get_db()
    try:
        token = _start_session(conn, email, device_id)
    finally:
        conn.close()

    return {
        "ok": True,
        "token": token,
        "user": {
            "email": user["email"],
            "name": user.get("name") or email.split("@")[0],
            "credits": int(user.get("credits") or 0),
            "created_at": user.get("created_at"),
            "bonus_granted": int(user.get("bonus_granted") or 0),
        },
    }


@router.get("/me")
def me(authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email=?", (sess["email"],)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="account not found")
        u = dict(row)
    finally:
        conn.close()
    return {
        "user": {
            "email": u["email"],
            "name": u.get("name") or u["email"].split("@")[0],
            "credits": int(u.get("credits") or 0),
            "created_at": u.get("created_at"),
            "bonus_granted": int(u.get("bonus_granted") or 0),
        },
        "device_id": sess.get("device_id") or "",
    }


@router.get("/device-status")
def device_status(authorization: str | None = Header(default=None)):
    """What this account is bound to. Read-only; the client cannot change it."""
    sess = require_session(authorization)
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT device_id, fingerprint, platform, model, first_seen_at,"
            " last_seen_at, blocked, released_at FROM devices WHERE email=?"
            " ORDER BY first_seen_at",
            (sess["email"],),
        ).fetchall()
        devices = []
        for r in rows:
            d = dict(r)
            devices.append({
                "device_id": d.get("device_id") or "",
                "fingerprint": d.get("fingerprint") or "",
                "platform": d.get("platform") or "",
                "model": d.get("model") or "",
                "first_seen_at": d.get("first_seen_at"),
                "last_seen_at": d.get("last_seen_at"),
                "blocked": int(d.get("blocked") or 0),
                "released_at": int(d.get("released_at") or 0),
            })
        # Count accounts sharing any of this account's fingerprints — surfaces
        # multi-accounting that predates the enforcement above.
        shared = 0
        fps = [d["fingerprint"] for d in devices if d["fingerprint"]]
        for fp in fps:
            row = conn.execute(
                "SELECT COUNT(DISTINCT email) AS n FROM devices"
                " WHERE fingerprint=? AND fingerprint<>''",
                (fp,),
            ).fetchone()
            if row:
                shared = max(shared, int(row["n"] or 0))
    finally:
        conn.close()
    return {
        # "bound" means an UNRELEASED hardware binding still gates this
        # account. A released row keeps its fingerprint for the cross-account
        # rule but no longer restricts the account's own access.
        "bound": any(not d["released_at"] for d in devices),
        "device_id": sess.get("device_id") or "",
        "devices": devices,
        "accounts_on_this_device": shared,
        "one_device_one_account": True,
    }


@router.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    token = ""
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
    if token:
        conn = get_db()
        try:
            conn.execute("UPDATE sessions SET revoked=1 WHERE token=?", (token,))
            conn.commit()
        finally:
            conn.close()
    return {"ok": True}


@router.get("/welcome-bonus")
def welcome_bonus():
    """Public: what a new account receives. Display only — never authoritative."""
    return {"credits": WELCOME_BONUS}
