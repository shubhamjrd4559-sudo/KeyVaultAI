"""Shared MongoDB connection factory.

Returns a database handle when MONGODB_URI is configured, or None when not.
Never exposes connection strings, credentials, or exception details through this
module's public interface.

Usage:
    from apps.common.database import get_db

    db = get_db()
    if db is None:
        # MongoDB is not configured or unavailable
        ...
"""
import logging
from typing import Optional

from django.conf import settings
from pymongo import MongoClient

logger = logging.getLogger(__name__)

_client: Optional[MongoClient] = None


def get_client() -> Optional[MongoClient]:
    """Return (or lazily create) the shared MongoClient.

    Returns None if MONGODB_URI is empty or the client cannot be created.
    The client is module-level so it is reused across requests.
    """
    global _client
    if _client is None:
        uri = getattr(settings, "MONGODB_URI", "")
        if not uri:
            return None
        try:
            _client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5_000,
                connectTimeoutMS=5_000,
            )
        except Exception:
            logger.exception("Failed to create MongoDB client — database features unavailable.")
            return None
    return _client


def get_db():
    """Return the configured MongoDB database, or None if unavailable.

    Always check the return value before use:
        db = get_db()
        if db is None:
            raise SomeServiceError("Database is not configured.")
    """
    client = get_client()
    if client is None:
        return None
    db_name = getattr(settings, "MONGODB_DATABASE", "keyvaultai")
    return client[db_name]
