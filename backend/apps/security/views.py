"""Security Engine API views.

Endpoints:
  GET /api/v1/security/summary/       — vault-wide security posture
  GET /api/v1/security/credentials/   — per-credential security analysis

All endpoints require a valid JWT.  user_id is ALWAYS sourced from
request.user (the validated JWT payload) — NEVER from the request body,
URL, or query string.

Response bodies NEVER contain:
  - plaintext passwords
  - encrypted ciphertext
  - encryption keys
  - any sensitive user data beyond publicly-known credential metadata

Reuse analysis is performed server-side, in-memory, for the
authenticated user only. Hashes used for comparison are discarded
immediately after the call completes.
"""
import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.users.authentication import JWTAuthentication
from apps.vault.repositories.credentials import (
    CredentialRepository,
    CredentialRepositoryError,
)
from apps.vault.services.encryption import get_encryption_service
from .services.analyzer import SecurityAnalyzer

logger = logging.getLogger(__name__)


# ── Dependency factory (patchable in tests) ───────────────────────────────────

def _get_credential_repo():
    """Return a CredentialRepository or None if MongoDB is not configured."""
    from apps.common.database import get_db
    db = get_db()
    if db is None:
        return None
    return CredentialRepository(db)


# ── Helpers ───────────────────────────────────────────────────────────────────

_SERVICE_UNAVAILABLE = {
    "detail": "Security service temporarily unavailable."
}


class SecuritySummaryView(APIView):
    """GET /api/v1/security/summary/

    Returns the authenticated user's vault-wide security posture:
    - total credentials
    - counts by level (very_strong / strong / fair / weak)
    - reused credential count
    - average score
    - overall score and level

    Performs password-reuse analysis in-memory. Plaintext passwords exist
    only within the scope of the reuse detection call and are never returned.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.user_id  # from validated JWT — never from client

        repo = _get_credential_repo()
        if repo is None:
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            # Fetch lean scored docs (no encrypted_password field)
            scored_docs = repo.find_all_by_user(user_id=user_id)

            # Fetch encrypted passwords for reuse detection
            encrypted_items = repo.find_all_encrypted_for_user(user_id=user_id)
        except CredentialRepositoryError:
            logger.exception("Repository error during security summary for user.")
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        except Exception:
            logger.exception("Unexpected error building security summary.")
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            enc = get_encryption_service()
            reused_ids = SecurityAnalyzer.detect_reuse(
                encrypted_items=encrypted_items,
                decrypt_fn=enc.decrypt,
            )
            analyzer = SecurityAnalyzer()
            credential_results = analyzer.analyze(
                scored_docs=scored_docs,
                reused_ids=reused_ids,
            )
            summary = SecurityAnalyzer.build_summary(credential_results)
        except Exception:
            logger.exception("Unexpected error during security analysis.")
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        return Response({"summary": summary.to_dict()})


class SecurityCredentialsView(APIView):
    """GET /api/v1/security/credentials/

    Returns per-credential security analysis for the authenticated user:
    - credential_id
    - website_name
    - category
    - security_score
    - security_level
    - is_reused (bool)
    - alerts (list of safe alert label strings)

    Passwords are NEVER included in the response.
    Reuse detection is performed in-memory and hashes are discarded.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.user_id  # from validated JWT — never from client

        repo = _get_credential_repo()
        if repo is None:
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            scored_docs = repo.find_all_by_user(user_id=user_id)
            encrypted_items = repo.find_all_encrypted_for_user(user_id=user_id)
        except CredentialRepositoryError:
            logger.exception("Repository error during security credentials for user.")
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        except Exception:
            logger.exception("Unexpected error fetching credentials for security analysis.")
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            enc = get_encryption_service()
            reused_ids = SecurityAnalyzer.detect_reuse(
                encrypted_items=encrypted_items,
                decrypt_fn=enc.decrypt,
            )
            analyzer = SecurityAnalyzer()
            credential_results = analyzer.analyze(
                scored_docs=scored_docs,
                reused_ids=reused_ids,
            )
        except Exception:
            logger.exception("Unexpected error during per-credential security analysis.")
            return Response(_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        return Response({
            "credentials": [c.to_dict() for c in credential_results],
            "count": len(credential_results),
        })
