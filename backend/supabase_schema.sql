-- ============================================================================
-- Maccview — Supabase (PostgreSQL) schema
--
-- Paste this into Supabase Dashboard -> SQL Editor -> Run.
-- It mirrors backend/app/database.py exactly (all 15 tables), so the app can
-- talk to either store.
--
-- ---------------------------------------------------------------------------
-- SECURITY MODEL — read this before changing anything below.
--
-- The FastAPI backend is the ONLY client of this database. It connects with
-- the SERVICE ROLE key, which bypasses row level security. The phone app never
-- touches Postgres directly; it only talks to the backend.
--
-- So: RLS is enabled on every table and there are deliberately NO POLICIES.
-- That means the `anon` (publishable) key can read and write NOTHING. If that
-- key ever leaks from a client build, it is useless against this schema.
--
-- DO NOT add `create policy ... using (true)`. A previous version of this file
-- did exactly that, which would have let anyone holding the publishable key
-- read every account and mint themselves unlimited credits.
--
-- The service role key must NEVER be shipped in the app or committed.
-- ---------------------------------------------------------------------------
--
-- Note on timestamps: kept as unix seconds (bigint) to match the existing
-- Python, which calls int(time.time()) throughout. Converting to timestamptz
-- would be more idiomatic Postgres but touches every read and write in the
-- codebase — not worth it for this port.
-- ============================================================================


-- ----------------------------------------------------------------- users
create table if not exists public.users (
  id            bigint generated always as identity primary key,
  email         text unique not null,
  name          text not null default '',
  -- New accounts start at ZERO. Credits arrive only via the server-side
  -- welcome bonus, a verified purchase, or a redeem code.
  credits       integer not null default 0,
  created_at    bigint  not null,
  bonus_granted integer not null default 0,
  bonus_at      bigint  not null default 0,
  status        text    not null default 'active',
  last_seen_at  bigint  not null default 0
);

-- -------------------------------------------------------------- sessions
create table if not exists public.sessions (
  token        text primary key,
  email        text    not null,
  device_id    text    not null default '',
  created_at   bigint  not null,
  last_used_at bigint  not null default 0,
  expires_at   bigint  not null default 0,
  revoked      integer not null default 0
);

-- --------------------------------------------------------------- devices
create table if not exists public.devices (
  device_id     text primary key,
  email         text    not null default '',
  fingerprint   text    not null default '',
  platform      text    not null default '',
  model         text    not null default '',
  first_seen_at bigint  not null,
  last_seen_at  bigint  not null default 0,
  blocked       integer not null default 0,
  -- Set when an admin releases this account's device binding. The fingerprint
  -- is deliberately kept so the one-device-one-account rule still knows this
  -- handset backed an account.
  released_at   bigint  not null default 0
);

-- ------------------------------------------------------------- otp_codes
create table if not exists public.otp_codes (
  email       text primary key,
  code_hash   text    not null,
  purpose     text    not null default 'signup',
  attempts    integer not null default 0,
  created_at  bigint  not null,
  expires_at  bigint  not null,
  consumed_at bigint  not null default 0
);

-- ------------------------------------------------------------- forecasts
create table if not exists public.forecasts (
  id          bigint generated always as identity primary key,
  user_email  text not null default '',
  asset       text not null,
  timeframe   text not null,
  direction   text not null,
  entry       double precision,
  tp          double precision,
  sl          double precision,
  confidence  double precision,
  created_at  bigint not null,
  outcome     text   not null default 'open',
  decided_at  bigint not null default 0
);

-- ----------------------------------------------------------------- scans
create table if not exists public.scans (
  id         bigint generated always as identity primary key,
  user_email text not null default '',
  mode       text not null,
  result     text not null,
  created_at bigint not null
);

-- --------------------------------------------------------- wallet_ledger
-- Every credit movement has a matching row here, written in the same
-- transaction as the balance change. balance_after is the running total.
create table if not exists public.wallet_ledger (
  id            bigint generated always as identity primary key,
  user_email    text    not null default '',
  delta         integer not null,
  reason        text    not null,
  balance_after integer not null default 0,
  created_at    bigint  not null
);

-- -------------------------------------------------------------- payments
create table if not exists public.payments (
  id           bigint generated always as identity primary key,
  reference    text unique not null,
  email        text    not null,
  plan         text    not null,
  amount_kobo  integer not null,
  credits      integer not null,
  status       text    not null default 'pending',
  created_at   bigint  not null,
  verified_at  bigint  not null default 0,
  raw_response text    not null default '',
  amount_gap   text    not null default ''
);

-- ------------------------------------------------------ overlay_settings
create table if not exists public.overlay_settings (
  id         bigint generated always as identity primary key,
  user_email text unique not null,
  settings   text not null,
  updated_at bigint not null
);

-- --------------------------------------------------------- notifications
create table if not exists public.notifications (
  id         bigint generated always as identity primary key,
  user_email text not null default '',
  title      text not null,
  body       text not null default '',
  "read"     integer not null default 0,
  created_at bigint not null
);

-- ---------------------------------------------------------------- assets
create table if not exists public.assets (
  symbol text primary key,
  name   text not null,
  kind   text not null
);

-- ---------------------------------------------------------------- models
-- The Oracle model catalogue. Credit cost lives HERE, not in code, so a new
-- model release or a price change is a row update rather than a deploy.
-- "key" is quoted because KEY is a reserved word in PostgreSQL.
create table if not exists public.models (
  "key"       text primary key,
  name        text    not null,
  version     text    not null default '1',
  credit_cost integer not null default 1,
  kind        text    not null default 'forecast',
  active      integer not null default 1,
  released_at bigint  not null default 0,
  retired_at  bigint  not null default 0,
  sort_order  integer not null default 0,
  notes       text    not null default '',
  updated_at  bigint  not null default 0
);

-- ---------------------------------------------------------------- admins
-- Admin privilege is a server-side grant, never a client claim. A separate
-- admin app authenticates against these rows; the consumer app never sees them.
create table if not exists public.admins (
  email        text primary key,
  role         text    not null default 'admin',
  granted_at   bigint  not null,
  granted_by   text    not null default '',
  active       integer not null default 1,
  last_seen_at bigint  not null default 0
);

-- Separate token namespace so an admin token can never be mistaken for a user
-- session (and vice versa).
create table if not exists public.admin_sessions (
  token        text primary key,
  email        text    not null,
  created_at   bigint  not null,
  last_used_at bigint  not null,
  expires_at   bigint  not null,
  revoked      integer not null default 0
);

-- ----------------------------------------------------------- admin_audit
-- Every privileged action, so a manual credit grant or ban is attributable.
create table if not exists public.admin_audit (
  id         bigint generated always as identity primary key,
  actor      text not null,
  action     text not null,
  target     text not null default '',
  detail     text not null default '',
  created_at bigint not null
);


-- --------------------------------------------------------------- indexes
create index if not exists idx_sessions_email  on public.sessions(email);
create index if not exists idx_devices_email   on public.devices(email);
create index if not exists idx_ledger_email    on public.wallet_ledger(user_email);
create index if not exists idx_payments_email  on public.payments(email);


-- ------------------------------------------------------------------- RLS
-- Enabled, with no policies on purpose. The service role key bypasses RLS, so
-- the backend works; the anon key gets nothing. See the header.
alter table public.users            enable row level security;
alter table public.sessions         enable row level security;
alter table public.devices          enable row level security;
alter table public.otp_codes        enable row level security;
alter table public.forecasts        enable row level security;
alter table public.scans            enable row level security;
alter table public.wallet_ledger    enable row level security;
alter table public.payments         enable row level security;
alter table public.overlay_settings enable row level security;
alter table public.notifications    enable row level security;
alter table public.assets           enable row level security;
alter table public.models           enable row level security;
alter table public.admins           enable row level security;
alter table public.admin_sessions   enable row level security;
alter table public.admin_audit      enable row level security;


-- ---------------------------------------------------------------- seeds
-- Model catalogue. Prices are data, not code. Adjust freely — the API reads
-- these rows at request time, so a change applies with no restart.
insert into public.models ("key", name, version, credit_cost, kind, active, sort_order, updated_at)
values
  ('oracle-vision-1',      'Oracle Vision 1',      '1',  1, 'forecast', 1, 10, 0),
  ('oracle-vision-1-mini', 'Oracle Vision 1 Mini', '1',  1, 'forecast', 1, 20, 0),
  ('scan-mini',            'Scan Mini',            '1',  5, 'scan',     1, 30, 0),
  ('scan-moderate',        'Scan Moderate',        '1', 10, 'scan',     1, 40, 0),
  ('scan-max',             'Scan Max',             '1', 15, 'scan',     1, 50, 0)
on conflict ("key") do nothing;

insert into public.assets (symbol, name, kind)
values
  ('EURUSD', 'Euro / US Dollar',        'forex'),
  ('GBPUSD', 'British Pound / US Dollar','forex'),
  ('GBPJPY', 'Pound / Japanese Yen',    'forex'),
  ('XAUUSD', 'Gold / US Dollar',        'metal'),
  ('XAGUSD', 'Silver / US Dollar',      'metal'),
  ('BTCUSD', 'Bitcoin / US Dollar',     'crypto')
on conflict (symbol) do nothing;


-- ===========================================================================
-- REPAIR: drop permissive policies left behind by an older version of this file
--
-- An earlier revision of this file created
--     create policy "open" on <table> for all using (true) with check (true);
-- on seven tables, six of them live ones (wallet_ledger and payments included).
-- `using (true)` means ANY holder of the anon/publishable key can read and
-- write every row, so that key could read all credit movements and insert
-- forged ledger entries.
--
-- Re-running this file does NOT clean them up on its own:
--   * `create table if not exists` skips tables that already exist, so the new
--     definitions never reach the pre-existing ones;
--   * `enable row level security` does NOT remove existing policies.
-- RLS enabled alongside a permissive policy is no protection whatsoever.
--
-- Safe to run repeatedly. Dropping a policy loses no data and cannot break the
-- backend — the service role bypasses RLS.
-- ===========================================================================
drop policy if exists "open" on public.profiles;
drop policy if exists "open" on public.forecasts;
drop policy if exists "open" on public.scans;
drop policy if exists "open" on public.wallet_ledger;
drop policy if exists "open" on public.payments;
drop policy if exists "open" on public.overlay_settings;
drop policy if exists "open" on public.notifications;


-- ===========================================================================
-- REPAIR: timestamp columns an older revision created as timestamptz
--
-- The previous revision declared `created_at timestamptz default now()`. The
-- app writes unix seconds (int(time.time())), and Postgres refuses:
--     cannot cast type integer to timestamp with time zone
-- On six of these tables that made the table UNWRITABLE — payments and
-- wallet_ledger included, so credits could not move at all.
--
-- `create table if not exists` never fixed it: the tables already existed, so
-- the new bigint definitions were never applied. This block does it explicitly.
--
-- ORDER MATTERS: `drop default` must come first. A `default now()` cannot be
-- auto-cast to bigint and blocks the type change with
-- "default for column ... cannot be cast automatically to type bigint".
--
-- Each conversion runs only when the column is not already bigint.
--
-- This used to be six unconditional `alter column ... type bigint using
-- coalesce(extract(epoch from ...))` statements, with a comment claiming they
-- were no-ops when the column was already bigint. That was wrong: Postgres
-- type-checks the USING expression at parse time whether or not a conversion
-- happens, and `extract(epoch from bigint)` does not exist. So on a FRESH
-- database — where the CREATE TABLE above already made these columns bigint —
-- the whole file aborted with
--     function pg_catalog.extract(unknown, bigint) does not exist
-- making the schema impossible to apply to a new database at all.
-- ===========================================================================
do $repair_timestamps$
declare
    r record;
begin
    for r in
        select * from (values
            ('forecasts',        'created_at'),
            ('scans',            'created_at'),
            ('wallet_ledger',    'created_at'),
            ('payments',         'created_at'),
            ('overlay_settings', 'updated_at'),
            ('notifications',    'created_at')
        ) as t(tbl, col)
    loop
        -- Only touch columns that exist AND are still a timestamp type.
        if exists (
            select 1
              from information_schema.columns
             where table_schema = 'public'
               and table_name   = r.tbl
               and column_name  = r.col
               and data_type   <> 'bigint'
        ) then
            execute format(
                'alter table public.%I alter column %I drop default',
                r.tbl, r.col);
            execute format(
                'alter table public.%I alter column %I type bigint '
                'using coalesce(extract(epoch from %I)::bigint, 0)',
                r.tbl, r.col, r.col);
            execute format(
                'alter table public.%I alter column %I set default 0',
                r.tbl, r.col);
            raise notice 'repaired %.% -> bigint', r.tbl, r.col;
        end if;
    end loop;
end
$repair_timestamps$;


-- ===========================================================================
-- REPAIR: columns an older revision never had
-- Same cause: the table already existed, so the new definition was skipped.
-- `wallet_ledger.balance_after` is the important one — without it every credit
-- movement fails, because move_credits always writes it.
-- ===========================================================================
alter table public.wallet_ledger    add column if not exists balance_after integer not null default 0;
alter table public.payments         add column if not exists verified_at   bigint  not null default 0;
alter table public.payments         add column if not exists raw_response  text    not null default '';
alter table public.payments         add column if not exists amount_gap    text    not null default '';
alter table public.overlay_settings add column if not exists id            bigint  not null default 0;


-- ===========================================================================
-- app_config  - broadcast state for forcing app upgrades
-- One row, CHECK(id=0). The admin writes min_version_code; the consumer app
-- calls GET /app/min-version on every launch and, if its bundled code is
-- below the threshold, renders an "upgrade required" screen instead of
-- letting the user in. If the table already exists on an older database,
-- it is created on demand by app/database.py::_migrate at next startup.
-- ===========================================================================
create table if not exists public.app_config (
  id                bigint  primary key default 0,
  min_version_code  bigint  not null default 0,
  min_version_name  text    not null default '',
  broadcast_message text    not null default '',
  broadcast_at      bigint  not null default 0,
  updated_at        bigint  not null default 0,
  updated_by        text    not null default '',
  check (id = 0)
);

insert into public.app_config (id, min_version_code)
values (0, 0)
on conflict (id) do nothing;

alter table public.app_config enable row level security;
