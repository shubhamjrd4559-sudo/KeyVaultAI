"""ML Engine API views — Milestone 6.

Endpoint:
  POST /api/v1/ml/predict/

Authentication: JWT required.

Privacy invariants:
  - user_id is ALWAYS sourced from request.user (validated JWT), never from client.
  - Response NEVER contains passwords, usernames, or ciphertext.
  - When a credential_id is provided, ownership is verified via vault repo before
    any data is fetched.
  - ML model operates only on derived numerical features.
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
from apps.security.services.analyzer import SecurityAnalyzer

from .features import extract_features, extract_features_from_score
from .model import predict

logger = logging.getLogger(__name__)

_ML_SERVICE_UNAVAILABLE = {"detail": "ML Engine temporarily unavailable."}


def _get_credential_repo():
    """Return a CredentialRepository or None if MongoDB is not configured."""
    from apps.common.database import get_db
    db = get_db()
    if db is None:
        return None
    return CredentialRepository(db)


class MLPredictView(APIView):
    """POST /api/v1/ml/predict/

    Accepts an optional ``credential_id``.

    With credential_id:
        - Fetches the credential from the vault (owner-scoped).
        - Decrypts password in-memory for accurate feature extraction.
        - Checks reuse for that credential using M5 reuse detection.
        - Returns ML risk prediction for that specific credential.

    Without credential_id:
        - Accepts ``security_score`` and ``security_level`` from the request body.
          (These are non-sensitive values already computed and stored by M5.)
        - Derives approximate features without touching any plaintext.
        - Returns ML risk prediction based on those safe values.

    NEVER returns passwords, usernames, ciphertext, or any sensitive data.
    user_id is ALWAYS from the validated JWT — never from the client.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = request.user.user_id  # from validated JWT — never from client

        credential_id = request.data.get("credential_id")

        if credential_id:
            return self._predict_for_credential(user_id, credential_id)
        else:
            return self._predict_from_score(request.data)

    # ── Prediction path A: specific credential (uses accurate features) ────────

    def _predict_for_credential(self, user_id: str, credential_id: str) -> Response:
        """Fetch, decrypt (temporarily), extract features, predict."""
        repo = _get_credential_repo()
        if repo is None:
            return Response(_ML_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            # Owner-scoped fetch — uses M3 ownership check
            doc = repo.find_by_id(credential_id=credential_id, user_id=user_id)
        except CredentialRepositoryError:
            logger.exception("Repository error fetching credential for ML predict.")
            return Response(_ML_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        if doc is None:
            return Response({"detail": "Credential not found."}, status=status.HTTP_404_NOT_FOUND)

        # Reuse detection for this credential (in-memory, hashes discarded)
        try:
            encrypted_items = repo.find_all_encrypted_for_user(user_id=user_id)
            enc = get_encryption_service()
            reused_ids = SecurityAnalyzer.detect_reuse(
                encrypted_items=encrypted_items,
                decrypt_fn=enc.decrypt,
            )
            is_reused = credential_id in reused_ids
        except Exception:
            logger.warning("Could not perform reuse detection for ML predict; defaulting to False.")
            is_reused = False

        # Decrypt password temporarily for accurate feature extraction
        try:
            enc = get_encryption_service()
            plaintext = enc.decrypt(doc["encrypted_password"])
            features = extract_features(
                plaintext_password=plaintext,
                security_score=doc.get("security_score", 0),
                is_reused=is_reused,
            )
            plaintext = None  # best-effort clear  # noqa: F841
        except Exception:
            logger.exception("Could not extract features for ML predict; using score-based fallback.")
            features = extract_features_from_score(
                security_score=doc.get("security_score", 0),
                security_level=doc.get("security_level", "weak"),
                is_reused=is_reused,
            )

        try:
            result = predict(features)
        except Exception:
            logger.exception("ML prediction failed.")
            return Response(_ML_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        # Safe response — no passwords, no ciphertext
        return Response({
            "credential_id": credential_id,
            **result.to_dict(),
        })

    # ── Prediction path B: score-only (no plaintext access) ───────────────────

    def _predict_from_score(self, data: dict) -> Response:
        """Derive approximate features from M5 score values — no plaintext needed."""
        try:
            security_score = int(data.get("security_score", 0))
            security_level = str(data.get("security_level", "weak"))
            is_reused = bool(data.get("is_reused", False))
        except (TypeError, ValueError):
            return Response(
                {"detail": "Invalid request data. Provide security_score (int) and security_level (str)."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if security_score < 0 or security_score > 100:
            return Response(
                {"detail": "security_score must be between 0 and 100."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if security_level not in ("weak", "fair", "strong", "very_strong"):
            return Response(
                {"detail": "security_level must be one of: weak, fair, strong, very_strong."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        features = extract_features_from_score(
            security_score=security_score,
            security_level=security_level,
            is_reused=is_reused,
        )

        try:
            result = predict(features)
        except Exception:
            logger.exception("ML prediction failed (score-based path).")
            return Response(_ML_SERVICE_UNAVAILABLE, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        return Response(result.to_dict())
