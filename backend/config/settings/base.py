import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "unsafe-development-key-replace-me")
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = [host.strip() for host in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if host.strip()]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "apps.common",
    "apps.users",    # Milestone 2 — Authentication
    "apps.audit",    # Milestone 2 — Audit logging
    "apps.vault",    # Milestone 3 — Secure Password Vault
    "apps.security", # Milestone 5 — Security Engine
    "apps.ml_engine", # Milestone 6 — ML Risk Prediction Engine
]


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.path.join(BASE_DIR, "db.sqlite3")}}

MONGODB_URI = os.environ.get("MONGODB_URI", "")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "keyvaultai")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_TIME_LIMIT = 300

# JWT — secret falls back to DJANGO_SECRET_KEY when JWT_SECRET_KEY is not set.
# Always configure a separate JWT_SECRET_KEY in production.
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    # Custom JWT authentication introduced in Milestone 2.
    # Per-view overrides (authentication_classes = []) bypass this for public endpoints.
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.users.authentication.JWTAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    # Avoids importing Django's built-in auth models (not installed).
    "UNAUTHENTICATED_USER": None,
}

CORS_ALLOWED_ORIGINS = [origin.strip() for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if origin.strip()]
# Explicitly never allow all origins — production.py re-validates this.
CORS_ALLOW_ALL_ORIGINS = False
# Required so the browser sends the HttpOnly refresh cookie cross-origin
# (frontend on Vercel → backend on Railway). Must never be combined with
# CORS_ALLOW_ALL_ORIGINS=True — production.py enforces this.
CORS_ALLOW_CREDENTIALS = True

# Local development fallback: if CORS_ALLOWED_ORIGINS is not set, allow localhost.
# Production settings will override this and require a non-empty explicit list.
if not CORS_ALLOWED_ORIGINS and DEBUG:
    CORS_ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

STATIC_URL = "/static/"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

JWT_ACCESS_TOKEN_LIFETIME = timedelta(seconds=int(os.environ.get("JWT_ACCESS_TOKEN_LIFETIME", "300")))
JWT_REFRESH_TOKEN_LIFETIME = timedelta(seconds=int(os.environ.get("JWT_REFRESH_TOKEN_LIFETIME", "2592000")))

# AES-256-GCM credential encryption key.
# Must be a base64url-encoded 32-byte key (i.e. base64url(os.urandom(32))).
# It is required for vault encryption operations in every environment.
# Consider a KMS for production key rotation.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")

# Outbound mail uses Django's standard SMTP backend. Credentials stay on the API
# host and must never use a NEXT_PUBLIC_ frontend variable.
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True").lower() == "true"
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "False").lower() == "true"
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", "10"))
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:3000").rstrip("/")
EMAIL_VERIFICATION_TOKEN_TTL_SECONDS = int(
    os.environ.get("EMAIL_VERIFICATION_TOKEN_TTL_SECONDS", "86400")
)
PASSWORD_RESET_TOKEN_TTL_SECONDS = int(
    os.environ.get("PASSWORD_RESET_TOKEN_TTL_SECONDS", "1800")
)
