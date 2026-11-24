"""Maccview backend settings — env reads with pydantic-settings when available."""
import os

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except Exception:
    pass

try:
    from pydantic_settings import BaseSettings  # type: ignore

    class Settings(BaseSettings):
        PAYSTACK_SECRET_KEY: str = ""
        PAYSTACK_PUBLIC_KEY: str = ""
        SUPABASE_URL: str = ""
        SUPABASE_KEY: str = ""
        PORT: int = 8101
        HOST: str = "0.0.0.0"
        DATABASE_PATH: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "maccview.db")

        # Which store the app talks to.
        #   "sqlite"   — the local file above. Zero setup, good for dev.
        #   "postgres" — Supabase. Requires DATABASE_URL.
        # Everything else in the codebase is dialect-agnostic: database.py
        # translates on the way out, so no call site knows the difference.
        DB_BACKEND: str = "sqlite"

        # Postgres connection string, used only when DB_BACKEND=postgres.
        # Supabase gives you this under Project Settings -> Database ->
        # Connection string -> URI. Use the SERVICE ROLE credentials, never the
        # anon key, and never ship this to a client.
        #   postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
        DATABASE_URL: str = ""
        # Market-data keys. The Oracle Vision tunnel that used to live here is
        # retired — forecasts are scored by Goose Feather 1.6 in Maccview's own
        # Cloudflare Worker, addressed by MACCVIEW_MODEL_URL below.
        TWELVEDATA_KEY: str = ""      # forex / metals / index candles
        FINNHUB_KEY: str = ""         # stocks + news (optional for v1)
        OANDA_TOKEN: str = ""         # forex / metals fallback
        OANDA_ACCOUNT: str = ""       # Oanda account id
        OANDA_ENV: str = "practice"   # practice | live

        # Signup OTP delivery. Without these, codes are printed to the
        # server console and never returned over the wire in live mode.
        SMTP_HOST: str = ""
        SMTP_PORT: int = 587
        SMTP_USER: str = ""
        SMTP_PASS: str = ""
        SMTP_FROM: str = ""

        # Server-side pepper for hashing OTP codes. Set a long random value
        # in production; the default only keeps local dev deterministic.
        SESSION_PEPPER: str = ""

        # Local development escape hatch. When true, signup OTP codes are
        # returned in the API response so the flow can be tested without an
        # SMTP server. MUST stay false in production.
        DEV_RETURN_OTP: bool = False

        # Admin bootstrap. Comma-separated emails promoted to admin at startup.
        # The first entry becomes 'owner' (may grant/revoke other admins);
        # the rest become 'admin'. This is the ONLY way to create the first
        # admin — there is no self-service escalation endpoint.
        ADMIN_EMAILS: str = ""

        # Where Paystack sends the browser after a completed checkout. Needed
        # for the hosted-page fallback (used when the inline library is not
        # available): without it the customer is stranded on Paystack's success
        # page with no way back. Leave empty to derive it from the caller's
        # Origin header, which is the app's own webview in practice.
        CALLBACK_URL: str = ""

        # Goose Feather 1.6 pipeline, standalone. Maccview owns the scorer
        # Worker; no desk session, Origin or signed transport is involved.
        ALOD_RELAY_URL: str = "https://alod-relay.bigbuikemm.workers.dev"
        # Shipped default, not a placeholder: this Worker is deployed and
        # scoring (verified 2026-11-24, summit p=0.6026 on a 192-float test
        # vector, 0ms). Env still overrides it, so a redeploy to a different
        # account only needs MACCVIEW_MODEL_URL set.
        MACCVIEW_MODEL_URL: str = "https://maccview-model.bigbuikemm.workers.dev"
        LW_MODEL: str = "summit"      # summit | kampa | willow | base
        LW_CT: float = 0.60           # conviction threshold, 0.55 / 0.60 / 0.65 / 0.70

        class Config:
            env_file = ".env"
            extra = "ignore"

    settings = Settings()
except Exception:  # fallback: plain env reads, no hard dependency
    class _Fallback:
        PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
        PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY", "")
        SUPABASE_URL = os.getenv("SUPABASE_URL", "")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
        PORT = int(os.getenv("PORT", "8101"))
        TWELVEDATA_KEY = os.getenv("TWELVEDATA_KEY", "")
        FINNHUB_KEY = os.getenv("FINNHUB_KEY", "")
        OANDA_TOKEN = os.getenv("OANDA_TOKEN", "")
        OANDA_ACCOUNT = os.getenv("OANDA_ACCOUNT", "")
        OANDA_ENV = os.getenv("OANDA_ENV", "practice")
        SMTP_HOST = os.getenv("SMTP_HOST", "")
        SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
        SMTP_USER = os.getenv("SMTP_USER", "")
        SMTP_PASS = os.getenv("SMTP_PASS", "")
        SMTP_FROM = os.getenv("SMTP_FROM", "")
        SESSION_PEPPER = os.getenv("SESSION_PEPPER", "")
        DEV_RETURN_OTP = os.getenv("DEV_RETURN_OTP", "0").strip().lower() in ("1", "true", "yes")
        ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "")
        CALLBACK_URL = os.getenv("CALLBACK_URL", "")
        ALOD_RELAY_URL = os.getenv("ALOD_RELAY_URL", "https://alod-relay.bigbuikemm.workers.dev")
        MACCVIEW_MODEL_URL = os.getenv("MACCVIEW_MODEL_URL", "")
        LW_MODEL = os.getenv("LW_MODEL", "summit")
        LW_CT = float(os.getenv("LW_CT", "0.60"))
        DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")
        DATABASE_URL = os.getenv("DATABASE_URL", "")
        DATABASE_PATH = os.getenv(
            "DATABASE_PATH",
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "maccview.db"),
        )

    settings = _Fallback()
