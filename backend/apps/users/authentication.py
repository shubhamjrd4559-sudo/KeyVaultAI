"""DRF authentication class for JWT Bearer token validation.

Reads 'Authorization: Bearer <token>' and validates the JWT access token.
Sets request.user to an AuthenticatedUser instance on success.

The AuthenticatedUser object:
- Exposes user_id and email from the verified token payload.
- Sets is_authenticated = True so DRF's IsAuthenticated permission works.
- Never exposes the raw token string or any signing secret.

Per-view override example (public endpoint):
    class RegisterView(APIView):
        authentication_classes = []
        permission_classes = []
"""
import logging

import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .services.authentication import get_token_service

logger = logging.getLogger(__name__)


class AuthenticatedUser:
    """Lightweight identity object placed on request.user after JWT validation.

    Only carries data that was already in the verified token payload.
    user_id comes from the token's 'sub' claim — never from the request body.
    """

    def __init__(self, user_id: str, email: str) -> None:
        self.user_id = user_id
        self.email = email
        self.is_authenticated = True  # Required by DRF IsAuthenticated

    def __repr__(self) -> str:
        return f"AuthenticatedUser(user_id={self.user_id!r})"


class JWTAuthentication(BaseAuthentication):
    """Validates JWT Bearer tokens and returns an AuthenticatedUser."""

    def authenticate(self, request):
        """Return (AuthenticatedUser, raw_token) or None.

        Returns None (not 401) when there is no Authorization header, so that
        public endpoints (authentication_classes=[]) are unaffected and
        IsAuthenticated permissions properly return 401 for missing tokens.
        """
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header[len("Bearer "):].strip()
        if not token:
            return None

        try:
            payload = get_token_service().decode_access_token(token)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired.")
        except jwt.PyJWTError:
            raise AuthenticationFailed("Invalid access token.")

        user_id = payload.get("sub")
        email = payload.get("email")

        if not user_id or not email:
            raise AuthenticationFailed("Malformed token payload.")

        return (AuthenticatedUser(user_id=user_id, email=email), token)

    def authenticate_header(self, request) -> str:
        """Sent in WWW-Authenticate header on 401 responses."""
        return 'Bearer realm="KeyVaultAI API"'
