"""Rate-limiting abstraction for authentication endpoints.

Provides a clean interface for rate-limited sensitive actions. When Redis is
unavailable, operations fail closed rather than bypassing enforcement.

Implementations
---------------
NullRateLimiter   — raises when Redis cannot be reached.
RedisRateLimiter  — fixed-window counter backed by Redis.

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
RATE_LIMIT_VERIFY_EMAIL = "verify_email"
# Vault sensitive operations (Milestone 3)
RATE_LIMIT_REVEAL = "credential_reveal"
RATE_LIMIT_COPY = "credential_copy"

# (max_attempts, window_seconds)
_LIMITS: dict[str, tuple[int, int]] = {
    RATE_LIMIT_LOGIN: (10, 300),           # 10 attempts per 5 min
    RATE_LIMIT_REGISTER: (5, 3600),        # 5 registrations per hour
    RATE_LIMIT_REFRESH: (30, 300),         # 30 refreshes per 5 min
    RATE_LIMIT_PASSWORD_RESET: (3, 3600),  # 3 resets per hour
    RATE_LIMIT_VERIFY_EMAIL: (5, 3600),    # 5 verification attempts per hour
    RATE_LIMIT_REVEAL: (20, 300),          # 20 reveals per 5 min per key
    RATE_LIMIT_COPY: (30, 300),            # 30 copies per 5 min per key
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


class RateLimitUnavailableError(RuntimeError):
    """Raised when the configured limiter cannot enforce a request limit."""


# ── Null implementation (Redis unavailable) ──────────────────────────────────

class NullRateLimiter(RateLimiter):
    """Fail-closed limiter retained for compatibility with existing imports."""

    def is_allowed(self, action: str, key: str) -> bool:
        raise RateLimitUnavailableError("Rate limiting is temporarily unavailable.")

    def record(self, action: str, key: str) -> None:
        raise RateLimitUnavailableError("Rate limiting is temporarily unavailable.")

    def check_and_record(self, action: str, key: str) -> bool:
        raise RateLimitUnavailableError("Rate limiting is temporarily unavailable.")


# ── Redis implementation ──────────────────────────────────────────────────────

class RedisRateLimiter(RateLimiter):
    """Fixed-window rate limiter backed by Redis.

    Uses one Lua operation for the per-key counter and limit check. Redis errors
    raise RateLimitUnavailableError so callers can fail closed.
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    _CHECK_AND_RECORD_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
if count > tonumber(ARGV[1]) then
  return 0
end
return 1
"""

    def check_and_record(self, action: str, key: str) -> bool:
        limit, window_seconds = _LIMITS.get(action, (100, 60))
        try:
            return bool(self._redis.eval(
                self._CHECK_AND_RECORD_SCRIPT,
                1,
                self._key(action, key),
                limit,
                window_seconds,
            ))
        except Exception as exc:
            logger.warning("Redis error enforcing rate limit; blocking request. action=%s", action)
            raise RateLimitUnavailableError(
                "Rate limiting is temporarily unavailable."
            ) from exc

    @staticmethod
    def _key(action: str, key: str) -> str:
        return f"rl:{action}:{key}"

    def is_allowed(self, action: str, key: str) -> bool:
        limit, _ = _LIMITS.get(action, (100, 60))
        try:
            count = self._redis.get(self._key(action, key))
            return count is None or int(count) < limit
        except Exception as exc:
            logger.warning("Redis error during rate-limit check; blocking request. action=%s", action)
            raise RateLimitUnavailableError(
                "Rate limiting is temporarily unavailable."
            ) from exc

    def record(self, action: str, key: str) -> None:
        _, window_seconds = _LIMITS.get(action, (100, 60))
        try:
            rkey = self._key(action, key)
            pipe = self._redis.pipeline()
            pipe.incr(rkey)
            pipe.expire(rkey, window_seconds)
            pipe.execute()
        except Exception as exc:
            logger.warning("Redis error recording rate limit; blocking request. action=%s", action)
            raise RateLimitUnavailableError(
                "Rate limiting is temporarily unavailable."
            ) from exc


# ── Factory ───────────────────────────────────────────────────────────────────

def get_rate_limiter() -> RateLimiter:
    """Return Redis limiter or fail-closed NullRateLimiter when unavailable."""
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
        logger.warning("Redis unavailable; rate-limited operations will fail closed.")
        return NullRateLimiter()
