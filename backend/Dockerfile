# Maccview backend — container image for Fly / Koyeb / Railway / any Docker host.
#
# Not needed for Render, which runs Python natively off the Procfile. It is here
# so the same backend can be moved to a container host without rework.
#
# Build:  docker build -t maccview-backend backend
# Run:    docker run --rm -p 8101:8101 --env-file backend/.env maccview-backend

FROM python:3.12-slim

# Nothing to apt-get. psycopg[binary] bundles libpq, so there is no need for
# libpq-dev or a compiler toolchain — which is the whole reason the extra is
# specified in requirements.txt.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Requirements first, so the dependency layer is cached across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Hosts inject PORT (Render, Railway, Fly and Koyeb all do). Default to 8101,
# the same value app/config.py falls back to, so a plain
# `docker run -p 8101:8101` works without setting anything.
ENV PORT=8101
EXPOSE 8101

# No persistent volume is required: storage is Supabase Postgres, selected with
# DB_BACKEND=postgres + DATABASE_URL. If DB_BACKEND is left at its "sqlite"
# default the app writes ./data/maccview.db, which is ephemeral in a container —
# so set DB_BACKEND=postgres in production.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
