"""Maccview FastAPI entrypoint."""
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import get_app_config, get_db, grant_admin, init_db, seed
from .routers import admin, auth, feather, market, oracle, payments, wallet


def _bootstrap_admins() -> None:
    """Promote accounts listed in ADMIN_EMAILS.

    Idempotent and safe to run on every boot. The first entry is granted the
    'owner' role so exactly one account can manage other admins. Deliberately
    silent about failures: a missing account is created on first signup and
    promoted on the next boot, so startup never breaks on config.
    """
    raw = (getattr(settings, "ADMIN_EMAILS", "") or "").strip()
    if not raw:
        return
    emails = [e.strip().lower() for e in raw.split(",") if e.strip()]
    if not emails:
        return
    conn = get_db()
    try:
        for i, email in enumerate(emails):
            role = "owner" if i == 0 else "admin"
            try:
                grant_admin(conn, email, role, granted_by="bootstrap")
            except Exception:
                continue
        # Never leave a second owner behind if ADMIN_EMAILS was reordered.
        for row in conn.execute(
            "SELECT email FROM admins WHERE role='owner'"
        ).fetchall():
            if row["email"] not in emails[:1]:
                conn.execute(
                    "UPDATE admins SET role='admin' WHERE email=?", (row["email"],)
                )
        conn.commit()
    finally:
        conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed()
    _bootstrap_admins()
    yield


app = FastAPI(title="Maccview API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(market.router)
app.include_router(oracle.router)
app.include_router(feather.router)
app.include_router(wallet.router)
app.include_router(payments.router)
app.include_router(admin.router)


@app.on_event("startup")
def _startup() -> None:
    # Kept for backward compat with older runners; lifespan already inits.
    try:
        init_db()
        seed()
        _bootstrap_admins()
    except Exception:
        pass


@app.get("/")
def root():
    return {"name": "Maccview API", "version": "0.1.0", "health": "/health"}


@app.get("/health")
def health():
    return {"ok": True, "paystack_configured": bool(settings.PAYSTACK_SECRET_KEY)}


@app.get("/app/min-version")
def app_min_version():
    """Public. The consumer app calls this on every launch and, if its bundled
    version_code is below the threshold, renders an "upgrade required" screen
    instead of letting the user in. The admin app writes the threshold via
    POST /admin/app-config. A backend that is unreachable simply fails open -
    the caller does its normal sign-in flow and surfaces the network error
    itself; we do not block here because the version check is best-effort and
    a dead backend should not stop a working app from opening."""
    conn = get_db()
    try:
        cfg = get_app_config(conn)
    finally:
        conn.close()
    return {
        "min_version_code": cfg["min_version_code"],
        "min_version_name": cfg["min_version_name"],
        "broadcast_message": cfg["broadcast_message"],
        "broadcast_at": cfg["broadcast_at"],
    }


@app.get("/models")
def public_models():
    """Public catalogue — the app shows credit costs from here, never a
    hardcoded constant. Costs change server-side without a client release."""
    conn = get_db()
    try:
        rows = []
        for m in conn.execute(
            "SELECT key,name,version,credit_cost,kind,released_at,notes"
            " FROM models WHERE active=1 ORDER BY sort_order, credit_cost, key"
        ).fetchall():
            d = dict(m)
            rows.append({
                "key": d["key"],
                "name": d["name"],
                "version": d["version"],
                "credit_cost": int(d["credit_cost"]),
                "kind": d["kind"],
                "released_at": d["released_at"],
                "notes": d["notes"],
            })
    finally:
        conn.close()
    return {"models": rows, "currency": "credits"}
