"""Storage layer — SQLite by default, Postgres/Supabase when configured.

Tables: users, sessions, devices, otp_codes, forecasts, scans, wallet_ledger,
payments, overlay_settings, notifications, assets, models, admins,
admin_sessions, admin_audit.

Money rules enforced at this layer:
  * users.credits starts at 0. Credits are only ever added by an explicit,
    audited ledger write (welcome bonus, purchase, redeem). There is no
    implicit starting balance.
  * Every credit movement has a matching wallet_ledger row, written in the
    same transaction.

Dialect handling
----------------
Everything above this layer is written in the SQLite dialect and does not know
which store is underneath. `_connect()` returns a connection that translates on
the way out when the backend is Postgres:

  * `?` placeholders become `%s`
  * `INSERT OR IGNORE INTO t ...` becomes `INSERT INTO t ... ON CONFLICT DO NOTHING`

That is deliberate. Rewriting 119 call sites and 209 placeholders by hand would
be a large, silent-error-prone diff for zero behavioural gain; a single
translation point is auditable and testable in isolation.
"""
import os
import re
import secrets
import sqlite3
import time

from .config import settings

# A brand new account starts with nothing. Credits arrive only via the
# server-side welcome bonus, a verified purchase, or a redeem code.
STARTING_CREDITS = 0

# One-time signup bonus, granted server-side exactly once per account.
WELCOME_BONUS = 20

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT DEFAULT '',
  credits INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  bonus_granted INTEGER NOT NULL DEFAULT 0,
  bonus_at INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  last_seen_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  device_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  email TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  platform TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  released_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS otp_codes (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'signup',
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS forecasts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT DEFAULT '',
  asset TEXT NOT NULL,
  timeframe TEXT NOT NULL,
  direction TEXT NOT NULL,
  entry REAL, tp REAL, sl REAL,
  confidence REAL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT DEFAULT '',
  mode TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS wallet_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT DEFAULT '',
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL,
  balance_after INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reference TEXT UNIQUE NOT NULL,
  email TEXT NOT NULL,
  plan TEXT NOT NULL,
  amount_kobo INTEGER NOT NULL,
  credits INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  verified_at INTEGER DEFAULT 0,
  raw_response TEXT DEFAULT '',
  amount_gap TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS overlay_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT UNIQUE NOT NULL,
  settings TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT DEFAULT '',
  title TEXT NOT NULL,
  body TEXT DEFAULT '',
  read INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
  symbol TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL
);
-- ---------------------------------------------------------------- models
-- The Oracle model catalogue. Credit cost lives HERE, not in code, so a new
-- model release or a price change is a row update rather than a deploy.
-- `key` is the stable machine identifier the API charges against.
CREATE TABLE IF NOT EXISTS models (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1',
  credit_cost INTEGER NOT NULL DEFAULT 1,
  kind TEXT NOT NULL DEFAULT 'forecast',
  active INTEGER NOT NULL DEFAULT 1,
  released_at INTEGER NOT NULL DEFAULT 0,
  retired_at INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  notes TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0
);
-- ---------------------------------------------------------------- admins
-- Admin privilege is a server-side grant, never a client claim. A separate
-- admin app authenticates against these rows; the consumer app never sees them.
CREATE TABLE IF NOT EXISTS admins (
  email TEXT PRIMARY KEY,
  role TEXT NOT NULL DEFAULT 'admin',
  granted_at INTEGER NOT NULL,
  granted_by TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  last_seen_at INTEGER NOT NULL DEFAULT 0
);
-- Separate token namespace so an admin token can never be mistaken for a
-- user session (and vice versa).
CREATE TABLE IF NOT EXISTS admin_sessions (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
-- Every privileged action, so a manual credit grant or ban is attributable.
CREATE TABLE IF NOT EXISTS admin_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
CREATE INDEX IF NOT EXISTS idx_devices_email ON devices(email);
CREATE INDEX IF NOT EXISTS idx_ledger_email ON wallet_ledger(user_email);
CREATE INDEX IF NOT EXISTS idx_payments_email ON payments(email);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit(created_at);
CREATE INDEX IF NOT EXISTS idx_models_kind ON models(kind);
-- A single-row table (CHECK id = 0) carries the broadcast state the admin app
-- writes and the consumer app reads on launch. The id is hard-pinned so a
-- future multi-row variant cannot silently fork the meaning.
CREATE TABLE IF NOT EXISTS app_config (
  id INTEGER PRIMARY KEY DEFAULT 0,
  min_version_code INTEGER NOT NULL DEFAULT 0,
  min_version_name TEXT NOT NULL DEFAULT '',
  broadcast_message TEXT NOT NULL DEFAULT '',
  broadcast_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0,
  updated_by TEXT NOT NULL DEFAULT '',
  CHECK (id = 0)
);
"""


def backend() -> str:
    """Which store is active: 'sqlite' or 'postgres'."""
    raw = (getattr(settings, "DB_BACKEND", "sqlite") or "sqlite").strip().lower()
    if raw in ("postgres", "postgresql", "supabase", "pg"):
        return "postgres"
    return "sqlite"


def pg_translate(sql: str) -> str:
    """Rewrite a SQLite-dialect statement into Postgres dialect.

    Three differences matter for this codebase:
      * placeholders: `?` -> `%s`
      * `INSERT OR IGNORE INTO t ...` -> `INSERT INTO t ... ON CONFLICT DO NOTHING`
      * literal `%` -> `%%`

    That last one is easy to miss and breaks the app hard: psycopg treats `%`
    as the start of a placeholder, so any SQL containing a literal percent —
    `reason LIKE 'redeem%'` in wallet.py, for instance — raises
    "only '%s', '%b', '%t' are allowed as placeholders" and the request 500s.

    Escaping happens only when the statement still uses `?`, i.e. it is
    SQLite-dialect. A statement already written with `%s` is left alone, so
    hand-written Postgres SQL is not double-escaped.

    A `?` inside a string literal is left alone, so a value like 'why?' cannot
    corrupt the statement. `''` is treated as an escaped quote inside a literal.

    Deciding whether to escape: the codebase writes SQLite-dialect SQL with
    `?`. Anything already using `%s`/`%b`/`%t` is hand-written Postgres and must
    not be touched. Everything else has literal percents only.
    """
    has_qmark = "?" in sql
    has_pg_placeholder = re.search(r"%(?:[sbt]|%)", sql) is not None

    # `INSERT OR IGNORE` is a DIALECT difference, not a placeholder concern, so
    # it must be rewritten on every statement — including parameterless ones.
    #
    # This used to live after the early return below, which meant a bare
    #     INSERT OR IGNORE INTO app_config (id, min_version_code) VALUES (0, 0)
    # had no "?" in it, returned early, and reached Postgres with SQLite syntax:
    #     psycopg.errors.SyntaxError: syntax error at or near "OR"
    # Anything with placeholders worked fine and hid the defect for years.
    if re.search(r"\bINSERT\s+OR\s+IGNORE\b", sql, re.I):
        sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\b", "INSERT", sql, flags=re.I)
        if not re.search(r"\bON\s+CONFLICT\b", sql, re.I):
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    if not has_qmark:
        # No placeholders at all. Either it is already Postgres (leave it), or
        # it is a parameterless statement whose `%` are literal (escape them).
        if has_pg_placeholder:
            return sql
        return sql.replace("%", "%%")

    # Escape literal percents FIRST, while the statement still has no
    # placeholders of its own — otherwise the %s we are about to insert would
    # be escaped too.
    sql = sql.replace("%", "%%")

    out = []
    in_str = False
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if in_str:
            out.append(ch)
            if ch == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if ch == "'":
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "?":
            out.append("%s")
            i += 1
            continue
        out.append(ch)
        i += 1

    return "".join(out)


class _Row(dict):
    """A row that answers BOTH name and index access.

    sqlite3.Row supports `row["col"]` and `row[0]`. psycopg's dict_row returns a
    plain dict, where `row[0]` raises KeyError. Rather than rewrite every index
    access in the codebase (about twenty sites), the Postgres row is a dict
    subclass that also answers integer indices — so existing code keeps working
    on both engines.

    Iteration is deliberately left as dict's (yielding keys). Anything that
    needs the values should go through the column names or `dict(row)`, which
    is what the rest of the code already does.
    """

    __slots__ = ()

    def __getitem__(self, key):
        if isinstance(key, int):
            values = list(self.values())
            try:
                return values[key]
            except IndexError:
                raise IndexError("row index out of range: %r" % (key,))
        return super().__getitem__(key)


def _pg_row_factory(cursor):
    """psycopg row factory producing _Row instances."""
    from psycopg.rows import dict_row

    inner = dict_row(cursor)

    def make(values):
        return _Row(inner(values))

    return make


class _PostgresConn:
    """Connection adapter so callers keep speaking the SQLite dialect.

    Only the methods the codebase actually uses are forwarded. Anything
    SQLite-only (`executescript`, `PRAGMA`) is deliberately absent — those call
    sites are guarded by `backend()` checks instead of silently doing nothing.
    """

    dialect = "postgres"

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        return self._conn.execute(pg_translate(sql), params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        try:
            self._conn.rollback()
        except Exception:
            pass

    def close(self):
        self._conn.close()


def _pg_connect(url: str, attempts: int = 4):
    """Connect to Postgres, retrying transient failures.

    A hosted database fails transiently in ways a local file never does: DNS
    blips, pooler hiccups, brief network loss. Observed in practice here —
    `failed to resolve host ... getaddrinfo failed` on an otherwise healthy
    connection. Without a retry that surfaces as a 500 to the user for
    something that succeeds a moment later.

    Only connection setup is retried. Once a statement is running, a failure is
    a real failure and is raised — silently retrying a write would risk
    applying it twice.
    """
    import psycopg

    last = None
    for i in range(attempts):
        try:
            return _PostgresConn(
                psycopg.connect(url, row_factory=_pg_row_factory, connect_timeout=15)
            )
        except psycopg.OperationalError as e:
            last = e
            if i < attempts - 1:
                time.sleep(0.4 * (i + 1))
        except Exception:
            raise
    raise last


def _connect():
    if backend() == "postgres":
        url = (getattr(settings, "DATABASE_URL", "") or "").strip()
        if not url:
            raise RuntimeError(
                "DB_BACKEND=postgres but DATABASE_URL is empty. Set it in "
                "backend/.env to the Supabase connection string."
            )
        # _Row answers both row["col"] and row[0], matching sqlite3.Row, so no
        # row-access site needs to change.
        return _pg_connect(url)

    path = settings.DATABASE_PATH
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    # busy_timeout keeps concurrent writers (webhook + verify + request
    # handlers) from failing with "database is locked"; timeout is the
    # stdlib-level equivalent for the connect() call itself.
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
    except sqlite3.Error:
        # Pragmas are best-effort; never block startup on them.
        pass
    return conn


def table_columns(conn, table: str) -> set:
    """Column names for a table, in whichever dialect is active."""
    try:
        if backend() == "postgres":
            rows = conn.execute(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_schema = 'public' AND table_name = %s",
                (table,),
            ).fetchall()
            return {r["column_name"] for r in rows}
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    except Exception:
        return set()


def _pg_decl(decl: str) -> str:
    """Translate a SQLite column declaration to Postgres."""
    out = decl
    out = re.sub(r"\bINTEGER\b", "bigint", out, flags=re.I)
    out = re.sub(r"\bTEXT\b", "text", out, flags=re.I)
    return out


def _migrate(conn) -> None:
    """Additive column migrations, on BOTH backends.

    This used to early-return on Postgres on the assumption that
    supabase_schema.sql was always the final shape. That assumption is wrong
    whenever a table already existed from an older revision: `create table if
    not exists` skips it, so the new definitions never apply and the table
    quietly keeps the old columns. That is exactly how wallet_ledger ended up
    without `balance_after` and payments without `verified_at` — and without
    balance_after, credits cannot move at all.

    Running the same repair on both engines removes that whole failure mode.
    """
    wanted = {
        "users": {
            "bonus_granted": "INTEGER NOT NULL DEFAULT 0",
            "bonus_at": "INTEGER NOT NULL DEFAULT 0",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "last_seen_at": "INTEGER NOT NULL DEFAULT 0",
        },
        "wallet_ledger": {
            "balance_after": "INTEGER NOT NULL DEFAULT 0",
        },
        "payments": {
            "verified_at": "INTEGER DEFAULT 0",
            "raw_response": "TEXT DEFAULT ''",
            "amount_gap": "TEXT DEFAULT ''",
        },
        "forecasts": {
            "outcome": "TEXT DEFAULT 'open'",
            "decided_at": "INTEGER DEFAULT 0",
        },
        "devices": {
            # Set when an admin releases this account's device binding. A
            # released row keeps its fingerprint (so the cross-account rule in
            # device_owner() still knows this handset backed an account) but
            # stops gating the account's own access.
            "released_at": "INTEGER NOT NULL DEFAULT 0",
        },
        # The old Postgres schema keyed this table on user_id with no id column.
        "overlay_settings": {
            "id": "INTEGER NOT NULL DEFAULT 0",
        },
    }
    for table, cols in wanted.items():
        existing = table_columns(conn, table)
        if not existing:
            continue
        for name, decl in cols.items():
            if name in existing:
                continue
            d = _pg_decl(decl) if backend() == "postgres" else decl
            try:
                conn.execute('ALTER TABLE "%s" ADD COLUMN "%s" %s' % (table, name, d))
                conn.commit()
            except Exception:
                # Column may already exist, or the table may not be ours.
                # Best-effort: never block startup on a repair.
                try:
                    conn.rollback()
                except Exception:
                    pass

    # Legacy SQLite repair ONLY. Old local databases seeded users with
    # credits DEFAULT 84 and a demo account; this normalises that. It must not
    # run against Postgres, where it would rewrite real migrated balances.
    if backend() == "postgres":
        # Ensure single-row app_config exists on an old Postgres that predates
        # the table. The CHECK (id = 0) constraint stops a future multi-row
        # variant from silently forking the meaning.
        existing = table_columns(conn, "app_config")
        if not existing:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS public.app_config (
                  id BIGINT PRIMARY KEY DEFAULT 0,
                  min_version_code BIGINT NOT NULL DEFAULT 0,
                  min_version_name TEXT NOT NULL DEFAULT '',
                  broadcast_message TEXT NOT NULL DEFAULT '',
                  broadcast_at BIGINT NOT NULL DEFAULT 0,
                  updated_at BIGINT NOT NULL DEFAULT 0,
                  updated_by TEXT NOT NULL DEFAULT '',
                  CHECK (id = 0)
                )
            """)
            conn.execute("INSERT INTO public.app_config (id, min_version_code)"
                         " VALUES (0, 0) ON CONFLICT (id) DO NOTHING")
        conn.commit()
        return
    try:
        conn.execute(
            "UPDATE users SET bonus_granted=1, bonus_at=created_at"
            " WHERE bonus_granted=0 AND credits > 0"
        )
        conn.execute(
            "UPDATE users SET credits=0, bonus_granted=0, bonus_at=0"
            " WHERE bonus_granted=0 AND credits = 0"
        )
    except sqlite3.Error:
        pass
    conn.commit()


def init_db() -> None:
    conn = _connect()
    try:
        if backend() == "sqlite":
            conn.executescript(SCHEMA)
        # Postgres: the schema is applied once by pasting supabase_schema.sql
        # into the Supabase SQL editor. Creating it from the app would need DDL
        # rights the runtime should not hold, and would fight the reviewed file.
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def seed() -> None:
    """Reference data only. No user accounts are ever fabricated here."""
    conn = _connect()
    try:
        assets = [
            ("EURUSD", "Euro / US Dollar", "forex"),
            ("GBPJPY", "British Pound / Japanese Yen", "forex"),
            ("XAUUSD", "Gold / US Dollar", "metal"),
            ("XAGUSD", "Silver / US Dollar", "metal"),
            ("BTCUSD", "Bitcoin / US Dollar", "crypto"),
            ("NAS100", "Nasdaq 100 Index", "index"),
        ]
        for sym, name, kind in assets:
            conn.execute(
                "INSERT OR IGNORE INTO assets(symbol,name,kind) VALUES(?,?,?)",
                (sym, name, kind),
            )

        # Oracle model catalogue. Seeded once; afterwards these rows are the
        # source of truth and are edited through /admin/models, never in code.
        # Oracle Vision 1 and 1 Mini both launch at 1 credit.
        now = int(time.time())
        models = [
            # key,           name,                     ver, cost, kind,       order, notes
            ("oracle-vision-1",      "Oracle Vision 1",      "1", 1, "forecast", 10,
             "Flagship release. Single-asset directional forecast."),
            ("oracle-vision-1-mini", "Oracle Vision 1 Mini", "1", 1, "forecast", 20,
             "Compact release. Same credit cost as the flagship at launch."),
            ("scan-mini",            "Deep Scan Mini",       "1", 5, "scan",     30,
             "Ranks the board, quick pass."),
            ("scan-moderate",        "Deep Scan Moderate",   "1", 10, "scan",    40,
             "Wider universe, deeper scoring."),
            ("scan-max",             "Deep Scan Max",        "1", 15, "scan",    50,
             "Full universe, maximum depth."),
        ]
        for key, name, ver, cost, kind, order, notes in models:
            conn.execute(
                "INSERT OR IGNORE INTO models(key,name,version,credit_cost,kind,"
                "active,released_at,retired_at,sort_order,notes,updated_at)"
                " VALUES(?,?,?,?,?,1,?,0,?,?,?)",
                (key, name, ver, cost, kind, now, order, notes, now),
            )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Model catalogue — pricing is data, not code.
# --------------------------------------------------------------------------

def list_models(conn: sqlite3.Connection, kind: str = "", active_only: bool = True) -> list[dict]:
    """Catalogue rows, cheapest-to-priciest within a kind."""
    sql = "SELECT * FROM models WHERE 1=1"
    params: list = []
    if kind:
        sql += " AND kind=?"
        params.append(kind)
    if active_only:
        sql += " AND active=1"
    sql += " ORDER BY sort_order, credit_cost, key"
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_model(conn: sqlite3.Connection, key: str) -> dict | None:
    row = conn.execute("SELECT * FROM models WHERE key=?", ((key or "").strip(),)).fetchone()
    return dict(row) if row else None


def model_cost(conn: sqlite3.Connection, key: str, fallback: int = 0) -> int:
    """Credit cost for a model key. Returns `fallback` when unknown.

    Callers should prefer this over any constant so pricing changes take
    effect immediately, without a restart.
    """
    row = conn.execute(
        "SELECT credit_cost, active FROM models WHERE key=?", ((key or "").strip(),)
    ).fetchone()
    if row is None:
        return int(fallback)
    return int(row["credit_cost"])


def upsert_model(conn: sqlite3.Connection, key: str, **fields) -> dict:
    """Create or update a catalogue row. Only known columns are accepted."""
    allowed = {"name", "version", "credit_cost", "kind", "active",
               "released_at", "retired_at", "sort_order", "notes"}
    key = (key or "").strip()
    if not key:
        raise ValueError("model key required")
    now = int(time.time())
    existing = get_model(conn, key)
    if existing is None:
        cols = {"key": key, "updated_at": now, "released_at": now}
        for k, v in fields.items():
            if k in allowed and v is not None:
                cols[k] = v
        names = ",".join(cols.keys())
        marks = ",".join("?" for _ in cols)
        conn.execute(f"INSERT INTO models({names}) VALUES({marks})", tuple(cols.values()))
    else:
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed and v is not None:
                sets.append(f"{k}=?")
                params.append(v)
        if sets:
            sets.append("updated_at=?")
            params.append(now)
            params.append(key)
            conn.execute(f"UPDATE models SET {','.join(sets)} WHERE key=?", tuple(params))
    conn.commit()
    return get_model(conn, key) or {}


def get_db() -> sqlite3.Connection:
    return _connect()


# --------------------------------------------------------------------------
# Account creation — the single place a user row is born.
# --------------------------------------------------------------------------

def create_account(conn: sqlite3.Connection, email: str, name: str = "",
                   device_id: str = "") -> dict:
    """Create the account if absent and grant the welcome bonus exactly once.

    Returns the account dict. Safe to call repeatedly: an existing account is
    returned untouched, and the bonus is never granted twice.
    """
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email required")
    now = int(time.time())

    conn.execute(
        "INSERT OR IGNORE INTO users(email,name,credits,created_at,bonus_granted,bonus_at,status,last_seen_at)"
        " VALUES(?,?,?,?,0,0,'active',?)",
        (email, name or email.split("@")[0], STARTING_CREDITS, now, now),
    )
    if name:
        conn.execute(
            "UPDATE users SET name=? WHERE email=? AND (name IS NULL OR name='')",
            (name, email),
        )

    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    user = dict(row)

    if not user.get("bonus_granted"):
        # The UPDATE is guarded by `bonus_granted=0`, so only one concurrent
        # caller can actually grant it. Check that THIS call was the one that
        # did, otherwise a second caller would write a ledger row claiming a
        # bonus it never paid — leaving the ledger summing higher than the
        # real balance.
        cur = conn.execute(
            "UPDATE users SET credits = credits + ?, bonus_granted=1, bonus_at=?"
            " WHERE email=? AND bonus_granted=0",
            (WELCOME_BONUS, now, email),
        )
        granted = getattr(cur, "rowcount", 0) or 0
        if granted:
            conn.execute(
                "UPDATE users SET last_seen_at=? WHERE email=?", (now, email)
            )
            bal = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
            conn.execute(
                "INSERT INTO wallet_ledger(user_email,delta,reason,balance_after,created_at)"
                " VALUES(?,?,?,?,?)",
                (email, WELCOME_BONUS, "welcome bonus",
                 int(bal["credits"]) if bal else WELCOME_BONUS, now),
            )
    conn.commit()

    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    user = dict(row)
    if device_id:
        touch_device(conn, device_id, email)
    return user


def account_summary(conn: sqlite3.Connection, email: str) -> dict:
    """Public view of an account. Never exposes internal flags as authority."""
    row = conn.execute(
        "SELECT email,name,credits,created_at,bonus_granted FROM users WHERE email=?",
        ((email or "").strip().lower(),),
    ).fetchone()
    if row is None:
        return {}
    return {
        "email": row["email"],
        "name": row["name"] or "",
        "credits": int(row["credits"] or 0),
        "created_at": row["created_at"],
        "bonus_granted": int(row["bonus_granted"] or 0),
    }


def touch_device(conn: sqlite3.Connection, device_id: str, email: str,
                 fingerprint: str = "", platform: str = "", model: str = "") -> None:
    now = int(time.time())
    conn.execute(
        "INSERT OR IGNORE INTO devices(device_id,email,fingerprint,platform,model,first_seen_at,last_seen_at)"
        " VALUES(?,?,?,?,?,?,?)",
        (device_id, email, fingerprint, platform, model, now, now),
    )
    # Backfill attestation on a row that was first created without it, and
    # never overwrite a recorded fingerprint with an empty one.
    conn.execute(
        "UPDATE devices SET last_seen_at=?,"
        " email=COALESCE(NULLIF(email,''),?),"
        " fingerprint=CASE WHEN (?<>'') THEN ? ELSE fingerprint END,"
        " platform=CASE WHEN (?<>'') THEN ? ELSE platform END,"
        " model=CASE WHEN (?<>'') THEN ? ELSE model END"
        " WHERE device_id=?",
        (now, email, fingerprint, fingerprint, platform, platform, model, model, device_id),
    )
    conn.commit()


def device_owner(conn: sqlite3.Connection, fingerprint: str) -> str | None:
    """The account already bound to this hardware fingerprint, if any.

    This is the cross-account half of the one-device rule: a single physical
    handset must not be able to farm welcome bonuses by registering many
    email addresses under the same fingerprint.
    """
    fp = (fingerprint or "").strip()
    if not fp:
        return None
    row = conn.execute(
        "SELECT email FROM devices WHERE fingerprint=? AND fingerprint<>''"
        " ORDER BY first_seen_at LIMIT 1",
        (fp,),
    ).fetchone()
    return (row["email"] or "").strip().lower() if row and row["email"] else None


def device_blocked(conn: sqlite3.Connection, device_id: str, fingerprint: str = "") -> bool:
    """True when this device or fingerprint has been explicitly blocked."""
    did = (device_id or "").strip()
    fp = (fingerprint or "").strip()
    if did:
        row = conn.execute(
            "SELECT blocked FROM devices WHERE device_id=? AND blocked=1", (did,)
        ).fetchone()
        if row:
            return True
    if fp:
        row = conn.execute(
            "SELECT blocked FROM devices WHERE fingerprint=? AND fingerprint<>'' AND blocked=1",
            (fp,),
        ).fetchone()
        if row:
            return True
    return False


# --------------------------------------------------------------------------
# Admin privilege — a server-side grant. The consumer app never sees these.
# --------------------------------------------------------------------------

ADMIN_SESSION_TTL = 60 * 60 * 12   # 12 hours; shorter than a user session


def is_admin(conn: sqlite3.Connection, email: str) -> bool:
    row = conn.execute(
        "SELECT active FROM admins WHERE email=?", ((email or "").strip().lower(),)
    ).fetchone()
    return bool(row) and int(row["active"] or 0) == 1


def admin_role(conn: sqlite3.Connection, email: str) -> str:
    row = conn.execute(
        "SELECT role, active FROM admins WHERE email=?", ((email or "").strip().lower(),)
    ).fetchone()
    if not row or int(row["active"] or 0) != 1:
        return ""
    return (row["role"] or "").strip().lower()


def grant_admin(conn: sqlite3.Connection, email: str, role: str = "admin",
                granted_by: str = "") -> dict:
    """Promote an account. Idempotent — re-granting updates the role."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email required")
    now = int(time.time())
    conn.execute(
        "INSERT INTO admins(email,role,granted_at,granted_by,active,last_seen_at)"
        " VALUES(?,?,?,?,1,0)"
        " ON CONFLICT(email) DO UPDATE SET role=excluded.role, active=1,"
        " granted_by=excluded.granted_by",
        (email, (role or "admin").strip().lower(), now, granted_by or ""),
    )
    conn.commit()
    return dict(conn.execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone())


def revoke_admin(conn: sqlite3.Connection, email: str) -> bool:
    cur = conn.execute(
        "UPDATE admins SET active=0 WHERE email=?", ((email or "").strip().lower(),)
    )
    # Kill any live admin sessions for that account too.
    conn.execute(
        "UPDATE admin_sessions SET revoked=1 WHERE email=?",
        ((email or "").strip().lower(),),
    )
    conn.commit()
    return cur.rowcount > 0


def list_admins(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT email, role, granted_at, granted_by, active, last_seen_at"
        " FROM admins ORDER BY granted_at"
    ).fetchall()]


def new_admin_session(conn: sqlite3.Connection, email: str) -> str:
    """Issue an admin token. Distinct namespace from user sessions."""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn.execute(
        "INSERT INTO admin_sessions(token,email,created_at,last_used_at,expires_at,revoked)"
        " VALUES(?,?,?,?,?,0)",
        (token, (email or "").strip().lower(), now, now, now + ADMIN_SESSION_TTL),
    )
    conn.commit()
    return token


def resolve_admin_session(conn: sqlite3.Connection, token: str) -> dict | None:
    """Validate an admin token. Returns {email, role} or None."""
    if not token:
        return None
    row = conn.execute(
        "SELECT * FROM admin_sessions WHERE token=?", (token,)
    ).fetchone()
    if row is None:
        return None
    s = dict(row)
    now = int(time.time())
    if s.get("revoked") or (s.get("expires_at") or 0) < now:
        return None
    if not is_admin(conn, s["email"]):
        return None
    conn.execute("UPDATE admin_sessions SET last_used_at=? WHERE token=?", (now, token))
    conn.execute("UPDATE admins SET last_seen_at=? WHERE email=?", (now, s["email"]))
    conn.commit()
    return {"email": s["email"], "role": admin_role(conn, s["email"])}


def audit(conn: sqlite3.Connection, actor: str, action: str,
          target: str = "", detail: str = "") -> None:
    """Record a privileged action so it is attributable after the fact."""
    conn.execute(
        "INSERT INTO admin_audit(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)",
        ((actor or "").strip().lower(), action, target or "", detail or "", int(time.time())),
    )
    conn.commit()


def audit_log(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM admin_audit ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()]


# --------------------------------------------------------------------------
# Credit movement — the single audited writer.
# --------------------------------------------------------------------------

def move_credits(conn: sqlite3.Connection, email: str, delta: int, reason: str) -> int:
    """Apply a credit delta and record it. Returns the new balance.

    Refuses to take a balance below zero. Callers that need a guard should
    check the balance first inside the same transaction.
    """
    email = (email or "").strip().lower()
    row = conn.execute("SELECT credits FROM users WHERE email=?", (email,)).fetchone()
    if row is None:
        raise KeyError(f"no such account: {email}")
    current = int(row["credits"])
    new_balance = current + int(delta)
    if new_balance < 0:
        raise ValueError("insufficient credits")
    conn.execute("UPDATE users SET credits=? WHERE email=?", (new_balance, email))
    conn.execute(
        "INSERT INTO wallet_ledger(user_email,delta,reason,balance_after,created_at)"
        " VALUES(?,?,?,?,?)",
        (email, int(delta), reason, new_balance, int(time.time())),
    )
    return new_balance


def new_token() -> str:
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
#  app_config — broadcast state for forcing app upgrades
# ---------------------------------------------------------------------------
#
# The admin writes a minimum acceptable version_code here. Every consumer app
# on launch calls GET /app/min-version and, if its bundled code is lower,
# renders an "upgrade required" screen instead of letting the user in.
#
# One row, CHECK(id=0), so a future multi-row variant cannot silently fork
# the meaning. Reads are dead simple, no audit on reads, full audit on writes.


def get_app_config(conn) -> dict:
    row = conn.execute(
        "SELECT min_version_code, min_version_name, broadcast_message,"
        " broadcast_at, updated_at, updated_by"
        " FROM app_config WHERE id=0"
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO app_config (id, min_version_code) VALUES (0, 0)"
        )
        conn.commit()
        return {
            "min_version_code": 0, "min_version_name": "",
            "broadcast_message": "", "broadcast_at": 0,
            "updated_at": 0, "updated_by": "",
        }
    d = dict(row)
    d["min_version_code"] = int(d.get("min_version_code") or 0)
    d["broadcast_at"] = int(d.get("broadcast_at") or 0)
    d["updated_at"] = int(d.get("updated_at") or 0)
    return d


def update_app_config(conn, *, min_version_code=None, min_version_name=None,
                      broadcast_message=None, updated_by: str = "") -> dict:
    """Update broadcast fields. None leaves the column untouched."""
    fields = []
    values = []
    if min_version_code is not None:
        fields.append("min_version_code=?")
        values.append(int(min_version_code))
    if min_version_name is not None:
        fields.append("min_version_name=?")
        values.append(str(min_version_name))
    if broadcast_message is not None:
        fields.append("broadcast_message=?")
        values.append(str(broadcast_message))
        # broadcast_at advances only when a message is set, so an empty
        # message does not falsely reset the "last announced" timestamp.
        fields.append("broadcast_at=?")
        values.append(int(time.time()))
    fields.append("updated_at=?")
    values.append(int(time.time()))
    fields.append("updated_by=?")
    values.append(str(updated_by or ""))
    if not fields:
        return get_app_config(conn)
    # Ensure the row exists before we try to update it. This is parameterless
    # on purpose, which is exactly the shape pg_translate used to skip — see the
    # note in that function.
    conn.execute("INSERT OR IGNORE INTO app_config (id, min_version_code)"
                 " VALUES (0, 0)")
    conn.execute(
        f"UPDATE app_config SET {', '.join(fields)} WHERE id=0", tuple(values)
    )
    # Commit here, like every other mutating helper in this module (audit(),
    # move_credits(), touch_device()). psycopg runs with autocommit off, so
    # without this the UPDATE is discarded when the connection closes — the
    # broadcast silently did nothing and the floor stayed at 0.
    conn.commit()
    return get_app_config(conn)
