"""JWT token generation and validation service.

Access tokens:  short-lived (default 5 min), carry user_id + email.
Refresh tokens: longer-lived (default 30 days), carry user_id + JTI only.

Token types are encoded in the payload to prevent cross-use.
The signing secret is read from settings.JWT_SECRET_KEY at call time so
tests can override it via Django's test settings mechanism.

NEVER:
- log token strings
- return the JWT secret in any response
- accept tokens signed with a different secret
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Tuple

import jwt
from django.conf import settings

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_ACCESS_TYPE = "access"
_REFRESH_TYPE = "refresh"


def _secret() -> str:
    """Read the JWT signing secret from settings at call time."""
    return settings.JWT_SECRET_KEY


class TokenService:
    """Generates and validates JWT access and refresh tokens.

    Obtain an instance via get_token_service() for production use.
    Instantiate directly in tests to use Django's test settings.
    """

    def generate_access_token(self, user_id: str, email: str) -> str:
        """Return a signed JWT access token string."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "email": email,
            "type": _ACCESS_TYPE,
            "iat": now,
            "exp": now + settings.JWT_ACCESS_TOKEN_LIFETIME,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, _secret(), algorithm=_ALGORITHM)

    def generate_refresh_token(
        self, user_id: str
    ) -> Tuple[str, str, datetime]:
        """Return (token_string, jti, expires_at).

        The JTI must be stored in MongoDB so it can be revoked on logout.
        """
        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        expires_at = now + settings.JWT_REFRESH_TOKEN_LIFETIME
        payload = {
            "sub": user_id,
            "type": _REFRESH_TYPE,
            "iat": now,
            "exp": expires_at,
            "jti": jti,
        }
        token = jwt.encode(payload, _secret(), algorithm=_ALGORITHM)
        return token, jti, expires_at

    def decode_access_token(self, token: str) -> dict:
        """Decode and validate an access token.

        Raises jwt.PyJWTError subclasses on expiry, invalid signature, etc.
        Raises jwt.InvalidTokenError if the token type is not 'access'.
        """
        payload = jwt.decode(token, _secret(), algorithms=[_ALGORITHM])
        if payload.get("type") != _ACCESS_TYPE:
            raise jwt.InvalidTokenError(
                "Token type mismatch: expected access token."
            )
        return payload

    def decode_refresh_token(self, token: str) -> dict:
        """Decode and validate a refresh token.

        Raises jwt.PyJWTError subclasses on expiry, invalid signature, etc.
        Raises jwt.InvalidTokenError if the token type is not 'refresh'.
        """
        payload = jwt.decode(token, _secret(), algorithms=[_ALGORITHM])
        if payload.get("type") != _REFRESH_TYPE:
            raise jwt.InvalidTokenError(
                "Token type mismatch: expected refresh token."
            )
        return payload


# ── Module-level singleton ────────────────────────────────────────────────────

_token_service: "TokenService | None" = None


def get_token_service() -> TokenService:
    """Return the module-level TokenService singleton."""
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service
