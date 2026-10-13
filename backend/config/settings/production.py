import os
import base64
import binascii

from .base import *  # noqa: F403,F401

# ── Secret validation ─────────────────────────────────────────────────────────

if SECRET_KEY == "unsafe-development-key-replace-me":  # noqa: F405
    raise RuntimeError("DJANGO_SECRET_KEY must be configured in production.")

if not os.environ.get("JWT_SECRET_KEY"):
    raise RuntimeError(
        "JWT_SECRET_KEY must be set as a separate environment variable in production. "
        "Do not rely on the fallback to DJANGO_SECRET_KEY."
    )
if os.environ.get("JWT_SECRET_KEY") == SECRET_KEY:  # noqa: F405
    raise RuntimeError("JWT_SECRET_KEY must differ from DJANGO_SECRET_KEY in production.")

encryption_key = os.environ.get("ENCRYPTION_KEY", "")
if not encryption_key:
    raise RuntimeError("ENCRYPTION_KEY must be configured in production.")
try:
    decoded_encryption_key = base64.b64decode(
        encryption_key + "=" * (-len(encryption_key) % 4),
        altchars=b"-_",
        validate=True,
    )
except (ValueError, binascii.Error):
    raise RuntimeError("ENCRYPTION_KEY must be a base64url-encoded 32-byte key.") from None
if len(decoded_encryption_key) != 32:
    raise RuntimeError("ENCRYPTION_KEY must be a base64url-encoded 32-byte key.")

if not os.environ.get("MONGODB_URI"):
    raise RuntimeError("MONGODB_URI must be configured in production.")
mongo_uri_lower = os.environ.get("MONGODB_URI", "").lower()
if (not mongo_uri_lower.startswith("mongodb+srv://") and "tls=true" not in mongo_uri_lower) or "tls=false" in mongo_uri_lower:
    raise RuntimeError("Production MongoDB connections must use TLS (Atlas SRV URIs enable TLS by default).")
if not REDIS_URL.startswith("rediss://"):  # noqa: F405
    raise RuntimeError("REDIS_URL must use rediss:// TLS in production.")
if not os.environ.get("ALLOWED_HOSTS") or not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS:  # noqa: F405
    raise RuntimeError("ALLOWED_HOSTS must list explicit production hostnames.")

if not EMAIL_HOST or not DEFAULT_FROM_EMAIL:  # noqa: F405
    raise RuntimeError("EMAIL_HOST and DEFAULT_FROM_EMAIL must be configured in production.")
if EMAIL_USE_TLS and EMAIL_USE_SSL:  # noqa: F405
    raise RuntimeError("Configure only one of EMAIL_USE_TLS or EMAIL_USE_SSL.")
if not (EMAIL_USE_TLS or EMAIL_USE_SSL):  # noqa: F405
    raise RuntimeError("Production email must use TLS or SSL.")
if not FRONTEND_BASE_URL.startswith("https://"):  # noqa: F405
    raise RuntimeError("FRONTEND_BASE_URL must use HTTPS in production.")
if EMAIL_VERIFICATION_TOKEN_TTL_SECONDS <= 0 or PASSWORD_RESET_TOKEN_TTL_SECONDS <= 0:  # noqa: F405
    raise RuntimeError("Email token lifetimes must be positive values.")

# ── HTTPS / Transport security ────────────────────────────────────────────────
# These require HTTPS termination in front of Django (e.g. Nginx, Gunicorn+TLS,
# or a PaaS like Railway/Render that does TLS at the edge).

SECURE_SSL_REDIRECT = True          # Redirect all HTTP → HTTPS
SECURE_HSTS_SECONDS = 31536000      # 1 year HSTS
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ── Cookies ───────────────────────────────────────────────────────────────────
# The API is stateless JWT. These affect Django session / CSRF cookies if used.
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

# ── CORS ─────────────────────────────────────────────────────────────────────
# CORS_ALLOWED_ORIGINS is already populated from env in base.py.
# Ensure the allow-all flag is NEVER active in production.
CORS_ALLOW_ALL_ORIGINS = False  # type: ignore[assignment]

if not CORS_ALLOWED_ORIGINS:  # noqa: F405
    raise RuntimeError(
        "CORS_ALLOWED_ORIGINS must be set in production "
        "(comma-separated list of allowed frontend origins). "
        "Set the actual HTTPS origin of the deployed frontend."
    )
if any(not origin.startswith("https://") for origin in CORS_ALLOWED_ORIGINS):  # noqa: F405
    raise RuntimeError("Production CORS_ALLOWED_ORIGINS must contain only HTTPS origins.")

# ── Celery Beat schedule ──────────────────────────────────────────────────────
# The 72-hour Recently Deleted cleanup MUST run server-side.
# Requires: celery -A config.celery beat  (and)  celery -A config.celery worker
from celery.schedules import crontab  # noqa: E402

CELERY_BEAT_SCHEDULE = {
    "cleanup-expired-deleted-credentials": {
        "task": "apps.vault.tasks.permanent_delete_expired_credentials",
        "schedule": crontab(minute="*/5"),  # keep purge close to the 72-hour threshold
    },
}

# ── Debug must be off in production ──────────────────────────────────────────
DEBUG = False  # type: ignore[assignment]

