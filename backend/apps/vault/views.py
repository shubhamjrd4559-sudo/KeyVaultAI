"""Vault API views.

Views are thin orchestrators — all security logic is in the service layer.

CRITICAL: user_id is ALWAYS sourced from request.user (validated JWT).
It is NEVER taken from the URL, query string, or request body.
This prevents identity spoofing regardless of client input.

Exception mapping:
  CredentialNotFoundError      → 404 (same for not-found AND wrong-owner — IDOR prevention)
  CredentialServiceError       → 503 (MongoDB/encryption unavailable)
  TooManyAttemptsError         → 429
  Unexpected exceptions        → 503 with generic message (no internals leaked)

Response bodies NEVER contain:
  - plaintext passwords (except reveal/copy which return ONLY the password)
  - encrypted_password ciphertext
  - encryption keys
  - stack traces
"""
import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.users.authentication import JWTAuthentication
from .repositories.credentials import CredentialNotFoundError
from .serializers import (
    CreateCredentialSerializer,
    CredentialFilterSerializer,
    UpdateCredentialSerializer,
)
from .services.credential_service import (
    CredentialServiceError,
    CredentialService,
    TooManyAttemptsError,
)

logger = logging.getLogger(__name__)


# ── Dependency factory (patchable in tests) ───────────────────────────────────

def _get_credential_service() -> CredentialService:
    """Return a configured CredentialService. Patch this in tests to inject mocks."""
    from apps.audit.services.audit import get_audit_service
    from apps.common.database import get_db
    from apps.users.services.rate_limiting import get_rate_limiter
    from .repositories.credentials import CredentialRepository
    from .services.credential_service import CredentialService
    from .services.encryption import get_encryption_service

    db = get_db()
    repo = CredentialRepository(db) if db is not None else None
    return CredentialService(
        repo=repo,
        encryption_service=get_encryption_service(),
        rate_limiter=get_rate_limiter(),
        audit_service=get_audit_service(db),
    )


def _client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


# ── Exception helpers ─────────────────────────────────────────────────────────

def _handle_not_found(exc: CredentialNotFoundError) -> Response:
    """Return 404. Never reveal whether the resource exists but is unauthorized."""
    return Response({"detail": "Credential not found."}, status=status.HTTP_404_NOT_FOUND)


def _handle_service_error(exc: CredentialServiceError) -> Response:
    return Response({"detail": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


def _handle_rate_limit(exc: TooManyAttemptsError) -> Response:
    return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)


# ── Views ─────────────────────────────────────────────────────────────────────

class CredentialListCreateView(APIView):
    """
    GET  /api/v1/vault/credentials/   — list user's credentials
    POST /api/v1/vault/credentials/   — create a credential
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """List all credentials for the authenticated user with optional filters."""
        filter_ser = CredentialFilterSerializer(data=request.query_params)
        if not filter_ser.is_valid():
            return Response(filter_ser.errors, status=status.HTTP_400_BAD_REQUEST)

        data = filter_ser.validated_data
        filters = {}
        if "category" in data:
            filters["category"] = data["category"]
        if "favorite" in data:
            filters["favorite"] = data["favorite"]
        if "security_level" in data:
            filters["security_level"] = data["security_level"]
        search = data.get("search")

        try:
            svc = _get_credential_service()
            # user_id ALWAYS from JWT — never from query params
            credentials = svc.list_credentials(
                user_id=request.user.user_id,
                filters=filters or None,
                search=search,
            )
            return Response({"credentials": credentials, "count": len(credentials)})
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error listing credentials.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    def post(self, request):
        """Create a new credential for the authenticated user."""
        ser = CreateCredentialSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        d = ser.validated_data
        try:
            svc = _get_credential_service()
            credential = svc.create_credential(
                user_id=request.user.user_id,  # from JWT — never from body
                plaintext_password=d["password"],
                website_name=d["website_name"],
                website_url=d.get("website_url", ""),
                username=d.get("username", ""),
                email=d.get("email", ""),
                category=d.get("category", "general"),
                notes=d.get("notes", ""),
                favorite=d.get("favorite", False),
                ip_address=_client_ip(request),
            )
            return Response({"credential": credential}, status=status.HTTP_201_CREATED)
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error creating credential.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class CredentialDetailView(APIView):
    """
    GET    /api/v1/vault/credentials/{credential_id}/   — retrieve metadata
    PATCH  /api/v1/vault/credentials/{credential_id}/   — update fields
    DELETE /api/v1/vault/credentials/{credential_id}/   — delete
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, credential_id: str):
        """Return safe credential metadata. Never decrypts the password."""
        try:
            svc = _get_credential_service()
            credential = svc.get_credential(
                credential_id=credential_id,
                user_id=request.user.user_id,  # from JWT
            )
            return Response({"credential": credential})
        except CredentialNotFoundError as exc:
            return _handle_not_found(exc)
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error retrieving credential.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    def patch(self, request, credential_id: str):
        """Update allowed fields. If 'password' supplied, re-encrypts it."""
        ser = UpdateCredentialSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            svc = _get_credential_service()
            credential = svc.update_credential(
                credential_id=credential_id,
                user_id=request.user.user_id,  # from JWT
                updates=dict(ser.validated_data),
                ip_address=_client_ip(request),
            )
            return Response({"credential": credential})
        except CredentialNotFoundError as exc:
            return _handle_not_found(exc)
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error updating credential.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    def delete(self, request, credential_id: str):
        """Permanently delete a credential. Ownership verified by repository."""
        try:
            svc = _get_credential_service()
            svc.delete_credential(
                credential_id=credential_id,
                user_id=request.user.user_id,  # from JWT
                ip_address=_client_ip(request),
            )
            return Response(
                {"detail": "Credential deleted."}, status=status.HTTP_200_OK
            )
        except CredentialNotFoundError as exc:
            return _handle_not_found(exc)
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error deleting credential.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class CredentialRevealView(APIView):
    """POST /api/v1/vault/credentials/{credential_id}/reveal/

    Decrypts and returns the credential password to the authorized owner.
    Rate-limited. Audited.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, credential_id: str):
        try:
            svc = _get_credential_service()
            password = svc.reveal_password(
                credential_id=credential_id,
                user_id=request.user.user_id,  # from JWT
                ip_address=_client_ip(request),
            )
            # password is the plaintext — returned to the authorized user only.
            # Never log this response.
            return Response({"password": password}, status=status.HTTP_200_OK)
        except TooManyAttemptsError as exc:
            return _handle_rate_limit(exc)
        except CredentialNotFoundError as exc:
            return _handle_not_found(exc)
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error during password reveal.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class CredentialCopyView(APIView):
    """POST /api/v1/vault/credentials/{credential_id}/copy/

    Authenticated, authorized, rate-limited password access for clipboard use.
    The frontend/browser layer handles actual clipboard interaction.
    This backend records the audit event and returns the password to the owner.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, credential_id: str):
        try:
            svc = _get_credential_service()
            password = svc.copy_password(
                credential_id=credential_id,
                user_id=request.user.user_id,  # from JWT
                ip_address=_client_ip(request),
            )
            return Response(
                {
                    "password": password,
                    "note": "The frontend layer is responsible for clipboard interaction.",
                },
                status=status.HTTP_200_OK,
            )
        except TooManyAttemptsError as exc:
            return _handle_rate_limit(exc)
        except CredentialNotFoundError as exc:
            return _handle_not_found(exc)
        except CredentialServiceError as exc:
            return _handle_service_error(exc)
        except Exception:
            logger.exception("Unexpected error during password copy.")
            return Response(
                {"detail": "Vault service temporarily unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
