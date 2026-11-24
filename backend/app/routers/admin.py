"""Admin API — server-side privilege for a separate admin application.

Design notes:
  * Admin privilege is granted server-side only (`admins` table). A client can
    never claim it, and the consumer app has no admin UI.
  * Admin tokens live in `admin_sessions`, a namespace separate from user
    sessions, so one can never be replayed as the other.
  * Two ways in, both requiring an already-privileged account:
      POST /admin/token  — exchange a live user session for an admin token
      POST /admin/login  — email + OTP code, same code the app would use
  * Every mutating call writes to `admin_audit` so a manual credit grant or a
    ban is attributable after the fact.
  * Credit changes go through `move_credits`, the same audited writer the
    consumer app uses. There is no second path to a balance.

Bootstrap: set ADMIN_EMAILS in the backend .env (comma-separated). Those
accounts are promoted at startup. Without at least one admin, /admin is
unreachable by design — there is no self-service escalation.
"""
import time

from fastapi import APIRouter, Body, Header, HTTPException, Query
from pydantic import BaseModel

from ..database import (
    audit,
    audit_log,
    get_app_config,
    get_db,
    get_model,
    grant_admin,
    is_admin,
    list_admins,
    list_models,
    move_credits,
    new_admin_session,
    resolve_admin_session,
    revoke_admin,
    update_app_config,
    upsert_model,
)

router = APIRouter(prefix="/admin", tags=["admin"])


def _scalar(row, default=0):
    """First column of a one-row result, whatever the dialect named it.

    Two reasons this does not use index or name access:
      * sqlite3.Row supports `row[0]`; psycopg's dict_row returns a plain dict
        and `dict[0]` raises KeyError.
      * `COUNT(*)` is named "COUNT(*)" by SQLite but "count" by Postgres, so a
        column name is not portable either.
    Going through the values sidesteps both.
    """
    if row is None:
        return default
    try:
        return next(iter(dict(row).values()))
    except Exception:
        return default


# ---------------------------------------------------------------- auth gate

def require_admin(authorization: str | None) -> dict:
    """Raise 401 unless the caller holds a valid admin token."""
    token = ""
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="admin token required")
    conn = get_db()
    try:
        sess = resolve_admin_session(conn, token)
    finally:
        conn.close()
    if not sess:
        # Deliberately identical to a missing token: don't reveal which
        # accounts exist or which tokens were once valid.
        raise HTTPException(status_code=401, detail="admin token required")
    return sess


class TokenIn(BaseModel):
    email: str = ""
    code: str = ""


class CreditIn(BaseModel):
    delta: int
    reason: str = "manual adjustment"


class BanIn(BaseModel):
    reason: str = ""
    block_devices: bool = True


class AdminIn(BaseModel):
    email: str
    role: str = "admin"


class ModelIn(BaseModel):
    key: str
    name: str = ""
    version: str = "1"
    credit_cost: int = 1
    kind: str = "forecast"
    active: int = 1
    sort_order: int = 0
    notes: str = ""


# ---------------------------------------------------------------- entry

@router.post("/token")
def admin_token(authorization: str | None = Header(default=None)):
    """Exchange a live user session for an admin token.

    Convenient for the admin app: sign in normally, then upgrade. Refuses any
    account that is not already an admin.
    """
    from .auth import require_session
    sess = require_session(authorization)
    conn = get_db()
    try:
        if not is_admin(conn, sess["email"]):
            raise HTTPException(status_code=403, detail="not an admin")
        token = new_admin_session(conn, sess["email"])
        audit(conn, sess["email"], "admin.login", sess["email"], "via user session")
        role = ""
        row = conn.execute(
            "SELECT role FROM admins WHERE email=?", (sess["email"],)
        ).fetchone()
        role = (row["role"] if row else "admin") or "admin"
    finally:
        conn.close()
    return {"ok": True, "admin_token": token, "email": sess["email"], "role": role}


@router.post("/login")
def admin_login(body: TokenIn):
    """Verify an OTP code for an admin account and issue an admin token.

    Reuses the same OTP the app would send, so admin access still requires
    control of the account's mailbox.
    """
    from .auth import _constant_eq, _hash_code, _norm, _valid_email

    email = _norm(body.email)
    code = (body.code or "").strip()
    if not _valid_email(email) or not code:
        raise HTTPException(status_code=400, detail="invalid email or code")

    conn = get_db()
    try:
        if not is_admin(conn, email):
            # Same response as a bad code: don't confirm who is an admin.
            raise HTTPException(status_code=400, detail="incorrect code")
        row = conn.execute("SELECT * FROM otp_codes WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=400, detail="no code requested")
        rec = dict(row)
        now = int(time.time())
        if rec.get("consumed_at"):
            raise HTTPException(status_code=400, detail="code already used")
        if (rec.get("expires_at") or 0) < now:
            raise HTTPException(status_code=400, detail="code expired")
        if int(rec.get("attempts") or 0) >= 5:
            raise HTTPException(status_code=429, detail="too many attempts")
        if not _constant_eq(rec.get("code_hash") or "", _hash_code(email, code)):
            conn.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE email=?", (email,))
            conn.commit()
            raise HTTPException(status_code=400, detail="incorrect code")

        conn.execute("UPDATE otp_codes SET consumed_at=? WHERE email=?", (now, email))
        conn.commit()
        token = new_admin_session(conn, email)
        audit(conn, email, "admin.login", email, "via otp")
        arow = conn.execute("SELECT role FROM admins WHERE email=?", (email,)).fetchone()
    finally:
        conn.close()
    return {"ok": True, "admin_token": token, "email": email,
            "role": (arow["role"] if arow else "admin") or "admin"}


@router.post("/logout")
def admin_logout(authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    token = ""
    if authorization:
        parts = authorization.split()
        if len(parts) == 2:
            token = parts[1].strip()
    conn = get_db()
    try:
        conn.execute("UPDATE admin_sessions SET revoked=1 WHERE token=?", (token,))
        conn.commit()
        audit(conn, sess["email"], "admin.logout", sess["email"], "")
    finally:
        conn.close()
    return {"ok": True}


@router.get("/me")
def admin_me(authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    conn = get_db()
    try:
        admins = list_admins(conn)
    finally:
        conn.close()
    return {"email": sess["email"], "role": sess["role"], "admins": admins}


# ---------------------------------------------------------------- overview

@router.get("/stats")
def admin_stats(authorization: str | None = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    try:
        def one(sql, *p):
            return _scalar(conn.execute(sql, p).fetchone(), 0)
        now = int(time.time())
        day = now - 86400
        return {
            "users_total": one("SELECT COUNT(*) FROM users"),
            "users_active": one("SELECT COUNT(*) FROM users WHERE status='active'"),
            "users_banned": one("SELECT COUNT(*) FROM users WHERE status<>'active'"),
            "users_new_24h": one("SELECT COUNT(*) FROM users WHERE created_at>=?", day),
            "credits_outstanding": one("SELECT COALESCE(SUM(credits),0) FROM users"),
            "sessions_active": one("SELECT COUNT(*) FROM sessions WHERE revoked=0 AND expires_at>?", now),
            "devices_bound": one("SELECT COUNT(*) FROM devices"),
            "forecasts_total": one("SELECT COUNT(*) FROM forecasts"),
            "payments_total": one("SELECT COUNT(*) FROM payments"),
            "payments_success": one("SELECT COUNT(*) FROM payments WHERE status='success'"),
            "revenue_kobo": one("SELECT COALESCE(SUM(amount_kobo),0) FROM payments WHERE status='success'"),
            "revenue_naira": round(one("SELECT COALESCE(SUM(amount_kobo),0) FROM payments WHERE status='success'") / 100.0, 2),
            "ledger_rows": one("SELECT COUNT(*) FROM wallet_ledger"),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------- users

@router.get("/users")
def admin_users(
    q: str = Query(default=""),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: str = Query(default=""),
    authorization: str | None = Header(default=None),
):
    require_admin(authorization)
    conn = get_db()
    try:
        sql = ("SELECT email,name,credits,status,created_at,bonus_granted,last_seen_at"
               " FROM users WHERE 1=1")
        params: list = []
        if q:
            sql += " AND email LIKE ?"
            params.append(f"%{q.strip().lower()}%")
        if status:
            sql += " AND status=?"
            params.append(status.strip().lower())
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]

        users = []
        for r in conn.execute(sql, params).fetchall():
            d = dict(r)
            email = d["email"]
            d["devices"] = _scalar(conn.execute(
                "SELECT COUNT(*) FROM devices WHERE email=?", (email,)
            ).fetchone(), 0)
            d["is_admin"] = is_admin(conn, email)
            users.append(d)

        total = _scalar(conn.execute("SELECT COUNT(*) FROM users").fetchone(), 0)
    finally:
        conn.close()
    return {"users": users, "total": total, "limit": limit, "offset": offset}


@router.get("/users/{email}")
def admin_user_detail(email: str, authorization: str | None = Header(default=None)):
    require_admin(authorization)
    email = (email or "").strip().lower()
    conn = get_db()
    try:
        urow = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if urow is None:
            raise HTTPException(status_code=404, detail="no such account")
        u = dict(urow)
        devices = [dict(r) for r in conn.execute(
            "SELECT device_id,fingerprint,platform,model,first_seen_at,last_seen_at,blocked"
            " FROM devices WHERE email=?", (email,)).fetchall()]
        sessions = [dict(r) for r in conn.execute(
            "SELECT token,device_id,created_at,last_used_at,expires_at,revoked"
            " FROM sessions WHERE email=? ORDER BY created_at DESC", (email,)).fetchall()]
        ledger = [dict(r) for r in conn.execute(
            "SELECT delta,reason,balance_after,created_at FROM wallet_ledger"
            " WHERE user_email=? ORDER BY id DESC LIMIT 100", (email,)).fetchall()]
        payments = [dict(r) for r in conn.execute(
            "SELECT reference,plan,amount_kobo,credits,status,created_at,amount_gap"
            " FROM payments WHERE email=? ORDER BY created_at DESC LIMIT 100", (email,)).fetchall()]
        # Redact session tokens: the admin app never needs to replay them.
        for s in sessions:
            s["token"] = (s["token"] or "")[:8] + "…"
        u["is_admin"] = is_admin(conn, email)
    finally:
        conn.close()
    return {"user": u, "devices": devices, "sessions": sessions,
            "ledger": ledger, "payments": payments}


@router.post("/users/{email}/credits")
def admin_set_credits(email: str, body: CreditIn,
                      authorization: str | None = Header(default=None)):
    """Manual credit assignment. Positive grants, negative deducts."""
    sess = require_admin(authorization)
    email = (email or "").strip().lower()
    delta = int(body.delta)
    if delta == 0:
        raise HTTPException(status_code=400, detail="delta must be non-zero")
    conn = get_db()
    try:
        try:
            balance = move_credits(conn, email, delta, f"admin: {body.reason}")
        except KeyError:
            raise HTTPException(status_code=404, detail="no such account")
        except ValueError:
            raise HTTPException(status_code=409, detail="insufficient credits for that deduction")
        audit(conn, sess["email"], "credits.adjust", email,
              f"{delta:+d} ({body.reason}) -> {balance}")
    finally:
        conn.close()
    return {"ok": True, "email": email, "balance": balance, "delta": delta}


@router.post("/users/{email}/ban")
def admin_ban(email: str, body: BanIn,
              authorization: str | None = Header(default=None)):
    """Suspend an account: status flips, sessions die, devices are blocked."""
    sess = require_admin(authorization)
    email = (email or "").strip().lower()
    if email == sess["email"]:
        raise HTTPException(status_code=400, detail="refusing to ban your own admin account")
    conn = get_db()
    try:
        row = conn.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="no such account")
        conn.execute("UPDATE users SET status='banned' WHERE email=?", (email,))
        killed = conn.execute(
            "UPDATE sessions SET revoked=1 WHERE email=?", (email,)
        ).rowcount
        blocked = 0
        if body.block_devices:
            blocked = conn.execute(
                "UPDATE devices SET blocked=1 WHERE email=?", (email,)
            ).rowcount
        conn.commit()
        audit(conn, sess["email"], "user.ban", email,
              f"sessions_revoked={killed} devices_blocked={blocked} reason={body.reason}")
    finally:
        conn.close()
    return {"ok": True, "email": email, "status": "banned",
            "sessions_revoked": killed, "devices_blocked": blocked}


@router.post("/users/{email}/unban")
def admin_unban(email: str, authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    email = (email or "").strip().lower()
    conn = get_db()
    try:
        row = conn.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="no such account")
        conn.execute("UPDATE users SET status='active' WHERE email=?", (email,))
        unblocked = conn.execute(
            "UPDATE devices SET blocked=0 WHERE email=?", (email,)
        ).rowcount
        conn.commit()
        audit(conn, sess["email"], "user.unban", email,
              f"devices_unblocked={unblocked}")
    finally:
        conn.close()
    return {"ok": True, "email": email, "status": "active", "devices_unblocked": unblocked}


@router.post("/users/{email}/revoke-sessions")
def admin_revoke_sessions(email: str, authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    email = (email or "").strip().lower()
    conn = get_db()
    try:
        n = conn.execute("UPDATE sessions SET revoked=1 WHERE email=?", (email,)).rowcount
        conn.commit()
        audit(conn, sess["email"], "sessions.revoke", email, f"count={n}")
    finally:
        conn.close()
    return {"ok": True, "email": email, "sessions_revoked": n}


@router.post("/users/{email}/devices/release")
def admin_release_devices(email: str, authorization: str | None = Header(default=None)):
    """Release an account's device binding so it can sign in on another handset.

    Needed because a hardware-bound account is otherwise unrecoverable: if the
    user changes phone, the new handset's id differs from the bound one and
    `_device_conflict` refuses them at request-code, with no path back.

    The row is marked released rather than deleted, so its fingerprint is kept
    and the one-device-one-account rule still knows this handset backed an
    account. Re-binding happens automatically the next time the user signs in
    on a device.
    """
    sess = require_admin(authorization)
    email = (email or "").strip().lower()
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT device_id, released_at FROM devices WHERE email=?", (email,)
        ).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="no device bound to this account")
        now = int(time.time())
        n = 0
        for r in rows:
            if int(r["released_at"] or 0) > 0:
                continue
            conn.execute(
                "UPDATE devices SET released_at=? WHERE device_id=?", (now, r["device_id"])
            )
            n += 1
        conn.commit()
        audit(conn, sess["email"], "devices.release", email, f"released={n}")
    finally:
        conn.close()
    return {"ok": True, "email": email, "devices_released": n}


# ---------------------------------------------------------------- models

@router.get("/models")
def admin_models(authorization: str | None = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    try:
        return {"models": list_models(conn, active_only=False)}
    finally:
        conn.close()


@router.post("/models")
def admin_create_model(body: ModelIn, authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    if int(body.credit_cost) < 0:
        raise HTTPException(status_code=400, detail="credit_cost cannot be negative")
    conn = get_db()
    try:
        row = upsert_model(
            conn, body.key,
            name=body.name or body.key, version=body.version,
            credit_cost=int(body.credit_cost), kind=body.kind,
            active=int(body.active), sort_order=int(body.sort_order),
            notes=body.notes,
        )
        audit(conn, sess["email"], "model.create", body.key,
              f"cost={body.credit_cost} kind={body.kind}")
    finally:
        conn.close()
    return {"ok": True, "model": row}


@router.patch("/models/{key}")
def admin_update_model(key: str, body: dict = Body(default_factory=dict),
                       authorization: str | None = Header(default=None)):
    """Update pricing or metadata. This is how a price change ships: a row
    update, no deploy. Unknown fields are ignored by upsert_model."""
    sess = require_admin(authorization)
    conn = get_db()
    try:
        if get_model(conn, key) is None:
            raise HTTPException(status_code=404, detail="no such model")
        if "credit_cost" in body:
            try:
                cost = int(body["credit_cost"])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="credit_cost must be an integer")
            if cost < 0:
                raise HTTPException(status_code=400, detail="credit_cost cannot be negative")
            body["credit_cost"] = cost
        row = upsert_model(conn, key, **body)
        audit(conn, sess["email"], "model.update", key,
              ",".join(f"{k}={v}" for k, v in body.items()))
    finally:
        conn.close()
    return {"ok": True, "model": row}


# ---------------------------------------------------------------- audit + payments

@router.get("/audit")
def admin_audit(limit: int = Query(default=100, ge=1, le=1000),
                authorization: str | None = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    try:
        return {"entries": audit_log(conn, limit)}
    finally:
        conn.close()


@router.get("/payments")
def admin_payments(limit: int = Query(default=100, ge=1, le=500),
                   status: str = Query(default=""),
                   authorization: str | None = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    try:
        sql = "SELECT * FROM payments WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status=?"
            params.append(status.strip().lower())
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()
    return {"payments": rows}


@router.get("/admins")
def admin_list(authorization: str | None = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    try:
        return {"admins": list_admins(conn)}
    finally:
        conn.close()


@router.post("/admins")
def admin_add(body: AdminIn, authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    if sess["role"] != "owner":
        raise HTTPException(status_code=403, detail="only an owner may grant admin")
    conn = get_db()
    try:
        row = grant_admin(conn, body.email, body.role, granted_by=sess["email"])
        audit(conn, sess["email"], "admin.grant", body.email, f"role={body.role}")
    finally:
        conn.close()
    return {"ok": True, "admin": row}


@router.delete("/admins/{email}")
def admin_remove(email: str, authorization: str | None = Header(default=None)):
    sess = require_admin(authorization)
    if sess["role"] != "owner":
        raise HTTPException(status_code=403, detail="only an owner may revoke admin")
    email = (email or "").strip().lower()
    if email == sess["email"]:
        raise HTTPException(status_code=400, detail="refusing to revoke your own admin")
    conn = get_db()
    try:
        ok = revoke_admin(conn, email)
        audit(conn, sess["email"], "admin.revoke", email, f"found={ok}")
    finally:
        conn.close()
    return {"ok": True, "email": email, "revoked": ok}


# ---------------------------------------------------------------- app config
#
# Broadcast state. The admin writes a min_version_code here; every consumer app
# on launch calls GET /app/min-version (public) and, if its bundled code is
# below the threshold, renders an "upgrade required" screen instead of letting
# the user in. This is the lever that makes "lock the current build" real.


class AppConfigIn(BaseModel):
    min_version_code: int | None = None
    min_version_name: str | None = None
    broadcast_message: str | None = None


@router.get("/app-config")
def admin_get_app_config(authorization: str | None = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    try:
        return {"config": get_app_config(conn)}
    finally:
        conn.close()


@router.post("/app-config")
def admin_set_app_config(body: AppConfigIn,
                         authorization: str | None = Header(default=None)):
    """Broadcast a new minimum. Empty / None fields are left untouched so the
    admin can change only one without re-typing the rest. Every change is
    written to admin_audit so "who raised the floor and when" is answerable."""
    sess = require_admin(authorization)
    if body.min_version_code is not None and int(body.min_version_code) < 0:
        raise HTTPException(
            status_code=400, detail="min_version_code cannot be negative"
        )
    conn = get_db()
    try:
        before = get_app_config(conn)
        after = update_app_config(
            conn,
            min_version_code=body.min_version_code,
            min_version_name=body.min_version_name,
            broadcast_message=body.broadcast_message,
            updated_by=sess["email"],
        )
        diff = []
        for k in ("min_version_code", "min_version_name", "broadcast_message"):
            if before.get(k) != after.get(k):
                diff.append(f"{k}: {before[k]!r} -> {after[k]!r}")
        audit(conn, sess["email"], "app_config.broadcast", "",
              "; ".join(diff) if diff else "no-change")
    finally:
        conn.close()
    return {"ok": True, "config": after}
