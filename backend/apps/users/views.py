"""Authentication views.

Views are intentionally thin — all business logic lives in UserService.

Responsibilities of each view:
1. Deserialize and validate the request body via a serializer.
2. Delegate to the service layer.
3. Map domain exceptions to appropriate HTTP responses.
4. Return safe responses (no password_hash, no secrets, no stack traces).

user_id on protected endpoints comes ONLY from request.user (the validated JWT),
never from the request body, to prevent identity spoofing.

COOKIE AUTH DESIGN (Hybrid model):
- Refresh token: set as HttpOnly; Secure; SameSite=Strict cookie by the backend.
  Never exposed to JavaScript. Rotated on every use.
- Access token: returned in the JSON response body.
  Short-lived (5 min). Stored in React state (in-memory) only.
- CSRF: Not required for cookie-only refresh because the refresh cookie is
  SameSite=Strict and the endpoint only accepts JSON Content-Type (not form).
  Cross-origin form submissions cannot set Content-Type: application/json.
"""
import logging

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import JWTAuthentication
from .serializers import (
    EmailOnlySerializer,
    EmailTokenSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    RegistrationSerializer,
)
from .services.users import (
    AccountDisabledError,
    AuthenticationError,
    EmailNotVerifiedError,
    InvalidEmailTokenError,
    RegistrationError,
    TooManyAttemptsError,
)

logger = logging.getLogger(__name__)

# Cookie name for the refresh token — used in all set/delete operations.
_REFRESH_COOKIE = "kv_refresh"


# ── Cookie helpers ────────────────────────────────────────────────────────────

def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Attach the refresh token as an HttpOnly, Secure, SameSite=Strict cookie."""
    # TTL mirrors JWT_REFRESH_TOKEN_LIFETIME (in seconds).
    max_age = int(getattr(settings, "JWT_REFRESH_TOKEN_LIFETIME").total_seconds())
    response.set_cookie(
        _REFRESH_COOKIE,
        refresh_token,
        max_age=max_age,
        httponly=True,
        secure=not settings.DEBUG,  # Secure flag off only in local HTTP dev
        samesite="Strict",
        path="/api/v1/auth/",  # Scoped: only sent to auth endpoints
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Clear the refresh token cookie."""
    response.delete_cookie(
        _REFRESH_COOKIE,
        path="/api/v1/auth/",
        samesite="Strict",
    )


# ── Dependency factory (patchable in tests) ───────────────────────────────────

def _get_user_service():
    """Return a configured UserService. Patch this in tests to inject mocks."""
    from apps.audit.services.audit import get_audit_service
    from apps.common.database import get_db
    from .repositories.users import UserRepository
    from .services.authentication import get_token_service
    from .services.rate_limiting import get_rate_limiter
    from .services.users import UserService

    db = get_db()
    repo = UserRepository(db) if db is not None else None
    return UserService(
        user_repo=repo,
        token_service=get_token_service(),
        rate_limiter=get_rate_limiter(),
        audit_service=get_audit_service(db),
    )


def _client_ip(request) -> str:
    """Extract the client IP from the request, checking X-Forwarded-For first."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


# ── Views ─────────────────────────────────────────────────────────────────────

class RegisterView(APIView):
    """POST /api/v1/auth/register/"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            service = _get_user_service()
            user = service.register(
                email=serializer.validated_data["email"],
                password=serializer.validated_data["password"],
                full_name=serializer.validated_data["full_name"],
                ip_address=_client_ip(request),
            )
            return Response({"user": user}, status=status.HTTP_201_CREATED)
        except TooManyAttemptsError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        except RegistrationError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception:
            logger.exception("Unexpected error during registration.")
            return Response(
                {"detail": "Registration is temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class LoginView(APIView):
    """POST /api/v1/auth/login/

    On success:
      - Sets refresh_token as HttpOnly cookie (kv_refresh).
      - Returns access_token in the JSON body ONLY.
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            service = _get_user_service()
            tokens = service.login(
                email=serializer.validated_data["email"],
                password=serializer.validated_data["password"],
                ip_address=_client_ip(request),
            )
            response = Response(
                {
                    "access_token": tokens["access_token"],
                    "token_type": tokens["token_type"],
                },
                status=status.HTTP_200_OK,
            )
            _set_refresh_cookie(response, tokens["refresh_token"])
            return response
        except TooManyAttemptsError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        except EmailNotVerifiedError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        except AccountDisabledError:
            # Return the same 401 as invalid credentials — do not reveal the reason
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except AuthenticationError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception:
            logger.exception("Unexpected error during login.")
            return Response(
                {"detail": "Login is temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class LogoutView(APIView):
    """POST /api/v1/auth/logout/  (requires valid access token)

    Revokes the refresh token stored in the HttpOnly cookie and clears it.
    The request body is no longer required to carry the refresh_token.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            service = _get_user_service()
            # Prefer refresh token from HttpOnly cookie; fall back to body for
            # backwards compatibility during the transition period.
            refresh_token = request.COOKIES.get(_REFRESH_COOKIE) or (
                request.data.get("refresh_token", "") if request.data else ""
            )
            # user_id is taken from request.user (validated JWT) — NEVER from the body
            service.logout(
                refresh_token=refresh_token,
                user_id=request.user.user_id,
                ip_address=_client_ip(request),
            )
            response = Response(
                {"detail": "Logged out successfully."},
                status=status.HTTP_200_OK,
            )
            _clear_refresh_cookie(response)
            return response
        except Exception:
            logger.exception("Unexpected error during logout.")
            return Response(
                {"detail": "Logout is temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class TokenRefreshView(APIView):
    """POST /api/v1/auth/token/refresh/

    Reads the refresh token from the HttpOnly cookie, rotates it, and:
      - Sets the new refresh token as a new HttpOnly cookie.
      - Returns the new access token in the JSON body.
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        # Read refresh token from HttpOnly cookie first, then fall back to body
        # (body fallback keeps backwards compatibility for existing test clients).
        refresh_token = request.COOKIES.get(_REFRESH_COOKIE)
        if not refresh_token:
            # Fallback: allow body-supplied token (e.g. test clients, legacy)
            refresh_token = request.data.get("refresh_token", "")
        if not refresh_token:
            return Response(
                {"detail": "Refresh token is required."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        try:
            service = _get_user_service()
            tokens = service.refresh_tokens(
                refresh_token=refresh_token,
                ip_address=_client_ip(request),
            )
            response = Response(
                {
                    "access_token": tokens["access_token"],
                    "token_type": tokens["token_type"],
                },
                status=status.HTTP_200_OK,
            )
            _set_refresh_cookie(response, tokens["refresh_token"])
            return response
        except TooManyAttemptsError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        except AuthenticationError as exc:
            response = Response(
                {"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED
            )
            _clear_refresh_cookie(response)
            return response
        except Exception:
            logger.exception("Unexpected error during token refresh.")
            return Response(
                {"detail": "Token refresh is temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


# ── Email verification and password reset ─────────────────────────────────────

class VerifyEmailView(APIView):
    """POST /api/v1/auth/verify-email/"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = EmailTokenSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            _get_user_service().verify_email(serializer.validated_data["token"], _client_ip(request))
            return Response({"detail": "Email verified. You can now sign in."})
        except TooManyAttemptsError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except InvalidEmailTokenError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            logger.exception("Email verification is temporarily unavailable.")
            return Response({"detail": "Email verification is temporarily unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class ResendVerificationView(APIView):
    """POST /api/v1/auth/resend-verification/"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = EmailOnlySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            _get_user_service().resend_verification(serializer.validated_data["email"], _client_ip(request))
            return Response({"detail": "If the account needs verification, a new link will be sent."})
        except TooManyAttemptsError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except Exception:
            logger.exception("Verification email request is temporarily unavailable.")
            return Response({"detail": "Email service is temporarily unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class ForgotPasswordView(APIView):
    """POST /api/v1/auth/forgot-password/"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = EmailOnlySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            _get_user_service().request_password_reset(serializer.validated_data["email"], _client_ip(request))
            return Response({"detail": "If an account exists for that email, a reset link will be sent."})
        except TooManyAttemptsError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except Exception:
            logger.exception("Password reset request is temporarily unavailable.")
            return Response({"detail": "Password reset is temporarily unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class ResetPasswordView(APIView):
    """POST /api/v1/auth/reset-password/"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            _get_user_service().reset_password(
                serializer.validated_data["token"],
                serializer.validated_data["password"],
                _client_ip(request),
            )
            return Response({"detail": "Password reset. You can now sign in."})
        except TooManyAttemptsError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except (InvalidEmailTokenError, RegistrationError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            logger.exception("Password reset is temporarily unavailable.")
            return Response({"detail": "Password reset is temporarily unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
