from .base import *  # noqa: F403

if SECRET_KEY == "unsafe-development-key-replace-me":  # noqa: F405
    raise RuntimeError("DJANGO_SECRET_KEY must be configured in production.")
