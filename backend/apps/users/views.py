"""Authentication views.

Views are intentionally thin — all business logic lives in UserService.

Responsibilities of each view:
1. Deserialize and validate the request body via a serializer.
2. Delegate to the service layer.
3. Map domain exceptions to appropriate HTTP responses.
4. Return safe responses (no password_hash, no secrets, no stack traces).

user_id on protected endpoints comes ONLY from request.user (the validated JWT),
never from the request body, to prevent identity spoofing.
"""
import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import JWTAuthentication
from .serializers import (
    LoginSerializer,
    LogoutSerializer,
    RegistrationSerializer,
    TokenRefreshSerializer,
)
from .services.users import (
    AccountDisabledError,
    AuthenticationError,
    RegistrationError,
    TooManyAttemptsError,
)

logger = logging.getLogger(__name__)


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
    """POST /api/v1/auth/login/"""

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
            return Response(tokens, status=status.HTTP_200_OK)
        except TooManyAttemptsError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS
            )
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
    """POST /api/v1/auth/logout/  (requires valid access token)"""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            service = _get_user_service()
            # user_id is taken from request.user (validated JWT) — NEVER from the body
            service.logout(
                refresh_token=serializer.validated_data["refresh_token"],
                user_id=request.user.user_id,
                ip_address=_client_ip(request),
            )
            return Response(
                {"detail": "Logged out successfully."},
                status=status.HTTP_200_OK,
            )
        except Exception:
            logger.exception("Unexpected error during logout.")
            return Response(
                {"detail": "Logout is temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class TokenRefreshView(APIView):
    """POST /api/v1/auth/token/refresh/"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            service = _get_user_service()
            tokens = service.refresh_tokens(
                refresh_token=serializer.validated_data["refresh_token"],
                ip_address=_client_ip(request),
            )
            return Response(tokens, status=status.HTTP_200_OK)
        except TooManyAttemptsError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        except AuthenticationError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception:
            logger.exception("Unexpected error during token refresh.")
            return Response(
                {"detail": "Token refresh is temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


# ── Scaffolded endpoints (email infrastructure not yet implemented) ────────────

class VerifyEmailView(APIView):
    """POST /api/v1/auth/verify-email/  (scaffolded — not yet available)"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        return Response(
            {
                "detail": (
                    "Email verification is not yet available. "
                    "This feature is planned for a future milestone."
                )
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class ForgotPasswordView(APIView):
    """POST /api/v1/auth/forgot-password/  (scaffolded — not yet available)"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        return Response(
            {
                "detail": (
                    "Password reset emails are not yet available. "
                    "This feature is planned for a future milestone."
                )
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class ResetPasswordView(APIView):
    """POST /api/v1/auth/reset-password/  (scaffolded — not yet available)"""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        return Response(
            {
                "detail": (
                    "Password reset is not yet available. "
                    "This feature is planned for a future milestone."
                )
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
