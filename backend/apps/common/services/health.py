from typing import Literal

from django.conf import settings
from pymongo import MongoClient
from redis import Redis

ServiceState = Literal["ok", "unavailable", "not_configured"]


def _mongo_status() -> ServiceState:
    if not settings.MONGODB_URI:
        return "not_configured"
    try:
        client = MongoClient(settings.MONGODB_URI, serverSelectionTimeoutMS=1_000, connectTimeoutMS=1_000)
        client.admin.command("ping")
        client.close()
        return "ok"
    except Exception:
        # Details must never be returned by this public endpoint.
        return "unavailable"


def _redis_status() -> ServiceState:
    try:
        Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1).ping()
        return "ok"
    except Exception:
        # Details must never be returned by this public endpoint.
        return "unavailable"


def dependency_health() -> dict[str, ServiceState]:
    return {"mongodb": _mongo_status(), "redis": _redis_status()}
