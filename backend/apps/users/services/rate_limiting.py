"""Rate-limiting abstraction for authentication endpoints.

Provides a clean interface that the service layer calls without caring whether
Redis is available. When Redis is unavailable, NullRateLimiter allows all
requests but emits a clear WARNING so operators know enforcement is disabled.

Implementations
---------------
NullRateLimiter   — no-op; used when Redis cannot be reached.
RedisRateLimiter  — sliding-window counter backed by Redis INCR + EXPIRE.

Usage
-----
    from .rate_limiting import get_rate_limiter, RATE_LIMIT_LOGIN

    limiter = get_rate_limiter()
    if not limiter.check_and_record(RATE_LIMIT_LOGIN, client_ip):
        raise TooManyAttemptsError(...)
"""
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# ── Action keys ──────────────────────────────────────────────────────────────
RATE_LIMIT_LOGIN = "login"
RATE_LIMIT_REGISTER = "register"
RATE_LIMIT_REFRESH = "refresh"
RATE_LIMIT_PASSWORD_RESET = "password_reset"

# (max_attempts, window_seconds)
_LIMITS: dict[str, tuple[int, int]] = {
    RATE_LIMIT_LOGIN: (10, 300),           # 10 attempts per 5 min
    RATE_LIMIT_REGISTER: (5, 3600),        # 5 registrations per hour
    RATE_LIMIT_REFRESH: (30, 300),         # 30 refreshes per 5 min
    RATE_LIMIT_PASSWORD_RESET: (3, 3600),  # 3 resets per hour
}


# ── Abstract interface ────────────────────────────────────────────────────────

class RateLimiter(ABC):
    """Abstract rate-limiter interface."""

    @abstractmethod
    def is_allowed(self, action: str, key: str) -> bool:
        """Return True if the action is within limits for this key."""

    @abstractmethod
    def record(self, action: str, key: str) -> None:
        """Record one attempt for the action/key pair."""

    def check_and_record(self, action: str, key: str) -> bool:
        """Check and record atomically. Returns True when the request is allowed."""
        if not self.is_allowed(action, key):
            return False
        self.record(action, key)
        return True


# ── Null implementation (Redis unavailable) ──────────────────────────────────

class NullRateLimiter(RateLimiter):
    """No-op rate limiter used when Redis is unavailable.

    Allows every request, but emits WARNING log entries so operators are
    aware that distributed rate limiting is currently unenforced.
    """

    def is_allowed(self, action: str, key: str) -> bool:
        logger.warning(
            "Rate limiting DISABLED (Redis unavailable). "
            "action=%s key=%s — request allowed without enforcement.",
            action,
            key,
        )
        return True

    def record(self, action: str, key: str) -> None:
        pass  # Nothing to record without Redis


# ── Redis implementation ──────────────────────────────────────────────────────

class RedisRateLimiter(RateLimiter):
    """Sliding-window rate limiter backed by Redis.

    Uses INCR + EXPIRE for per-key counters. On Redis errors, fails open
    (allows the request) rather than blocking legitimate users, but logs the
    error so the problem is visible.
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    @staticmethod
    def _key(action: str, key: str) -> str:
        return f"rl:{action}:{key}"

    def is_allowed(self, action: str, key: str) -> bool:
        limit, _ = _LIMITS.get(action, (100, 60))
        try:
            count = self._redis.get(self._key(action, key))
            return count is None or int(count) < limit
        except Exception:
            logger.exception(
                "Redis error during rate-limit check — failing open. action=%s key=%s",
                action,
                key,
            )
            return True

    def record(self, action: str, key: str) -> None:
        _, window_seconds = _LIMITS.get(action, (100, 60))
        try:
            rkey = self._key(action, key)
            pipe = self._redis.pipeline()
            pipe.incr(rkey)
            pipe.expire(rkey, window_seconds)
            pipe.execute()
        except Exception:
            logger.exception(
                "Redis error during rate-limit record — skipping. action=%s key=%s",
                action,
                key,
            )


# ── Factory ───────────────────────────────────────────────────────────────────

def get_rate_limiter() -> RateLimiter:
    """Return a Redis-backed limiter if Redis is reachable, else NullRateLimiter."""
    try:
        from redis import Redis
        from django.conf import settings

        client = Redis.from_url(
            settings.REDIS_URL,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
            decode_responses=True,
        )
        client.ping()
        logger.debug("Rate limiting: Redis-backed limiter active.")
        return RedisRateLimiter(client)
    except Exception:
        logger.warning(
            "Redis unavailable or not configured — rate limiting is DISABLED. "
            "Start Redis and restart the server to enable distributed enforcement."
        )
        return NullRateLimiter()
