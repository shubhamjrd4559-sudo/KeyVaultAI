#!/bin/sh
# Release phase script: runs before new Railway instance serves traffic.
# Ensures MongoDB indexes exist before the web process starts.
#
# In Railway: set this as the "Deploy → Start Command" for the web service,
# prefixed before the actual gunicorn command.
# Or use it as a separate "Pre-Deploy" step via railway.toml (see docs).
set -e

echo "[preflight] Running Django system check…"
python manage.py check --deploy

echo "[preflight] Initializing MongoDB indexes (read-only preflight)…"
python manage.py ensure_mongodb_indexes

echo "[preflight] Applying MongoDB indexes…"
python manage.py ensure_mongodb_indexes --apply

echo "[preflight] Preflight complete. Starting gunicorn…"
exec gunicorn config.wsgi:application --bind "0.0.0.0:${PORT:-8000}" --workers 2 --threads 2 --timeout 30
