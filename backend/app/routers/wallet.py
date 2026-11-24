"""Wallet — balance, ledger, promo codes.

Identity comes from the session token. There is no way to read or move
another account's credits by passing an email.
"""
import time

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from ..database import get_db, move_credits
from ..routers.auth import require_session

router = APIRouter(prefix="/wallet", tags=["wallet"])

REDEEM_CODES = {
    "WELCOME20": 20,
    "CHRIS20": 20,
    "ORACLE50": 50,
}


@router.get("")
@router.get("/")
def get_wallet(authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    email = sess["email"]
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="account not found")
        u = dict(user)
        txs = conn.execute(
            "SELECT delta,reason,balance_after,created_at FROM wallet_ledger"
            " WHERE user_email=? ORDER BY id DESC LIMIT 20",
            (email,),
        ).fetchall()
        pay = conn.execute(
            "SELECT COALESCE(SUM(credits),0) AS c FROM payments WHERE email=? AND status='success'",
            (email,),
        ).fetchone()
        bonus = conn.execute(
            "SELECT COALESCE(SUM(delta),0) AS b FROM wallet_ledger"
            " WHERE user_email=? AND (reason LIKE 'redeem%' OR reason='welcome bonus')",
            (email,),
        ).fetchone()
        used = conn.execute(
            "SELECT COALESCE(SUM(-delta),0) AS u FROM wallet_ledger"
            " WHERE user_email=? AND delta<0",
            (email,),
        ).fetchone()
    finally:
        conn.close()
    credits = int(u.get("credits") or 0)
    return {
        "email": email,
        "credits": credits,
        "name": u.get("name") or email.split("@")[0],
        "member_since": u.get("created_at") or int(time.time()),
        "bonus_granted": int(u.get("bonus_granted") or 0),
        "naira_equivalent": credits * 50,   # 20 credits = N1000
        "ledger": [dict(t) for t in txs],
        "stats": {"purchased": int(pay["c"]), "bonus": int(bonus["b"]), "used": int(used["u"])},
    }


class RedeemIn(BaseModel):
    code: str


@router.post("/redeem")
def redeem(body: RedeemIn, authorization: str | None = Header(default=None)):
    sess = require_session(authorization)
    email = sess["email"]
    code = (body.code or "").strip().upper()
    if code not in REDEEM_CODES:
        return {"error": "invalid code", "credits_added": 0}
    amount = REDEEM_CODES[code]

    conn = get_db()
    try:
        row = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="account not found")
        # Single-use per code per account — prevents infinite bonus farming.
        prior = conn.execute(
            "SELECT id FROM wallet_ledger WHERE user_email=? AND reason=? LIMIT 1",
            (email, f"redeem {code}"),
        ).fetchone()
        if prior is not None:
            return {"error": "already redeemed", "code": code,
                    "credits_added": 0, "credits": int(row["credits"])}
        balance = move_credits(conn, email, amount, f"redeem {code}")
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "code": code, "credits_added": amount, "credits": balance}
