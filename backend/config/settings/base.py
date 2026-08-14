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
    "apps.users",   # Milestone 2 — Authentication
    "apps.audit",   # Milestone 2 — Audit logging
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

STATIC_URL = "/static/"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

JWT_ACCESS_TOKEN_LIFETIME = timedelta(seconds=int(os.environ.get("JWT_ACCESS_TOKEN_LIFETIME", "300")))
JWT_REFRESH_TOKEN_LIFETIME = timedelta(seconds=int(os.environ.get("JWT_REFRESH_TOKEN_LIFETIME", "2592000")))
