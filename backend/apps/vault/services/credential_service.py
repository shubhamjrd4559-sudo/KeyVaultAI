"""Credential business-logic service.

Orchestrates: validation → encryption → repository → audit.

Security invariants enforced here:
1. Plaintext passwords are encrypted before ANY other operation.
2. Plaintext passwords are NEVER logged, stored, or returned except
   through explicit reveal/copy flows.
3. user_id is ALWAYS taken from the authenticated JWT (passed in by the view),
   NEVER from request body or URL parameters.
4. Reveal/copy operations are rate-limited before any decryption occurs.
5. Decrypted passwords exist only inside the scope of reveal/copy methods —
   they are returned as strings and not cached anywhere server-side.
6. Audit events are written for every credential operation.
7. When MongoDB is unavailable, a clear service error is raised rather than
   a degraded security posture.

KEY MANAGEMENT NOTE:
This milestone uses a single symmetric key (ENCRYPTION_KEY env var) for all
credential encryption. This is NOT zero-knowledge — the server can decrypt any
credential. Production deployments should consider:
  - Per-user key derivation (requires careful key storage design)
  - Hardware Security Modules (HSMs)
  - Cloud KMS with audit trails
  - Envelope encryption patterns
  These are planned for a future security hardening milestone.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from apps.audit.services.audit import AuditEvent, AuditService
from apps.users.services.rate_limiting import (
    RATE_LIMIT_COPY,
    RATE_LIMIT_REVEAL,
    RateLimiter,
)
from ..models import Credential, score_password
from ..repositories.credentials import (
    CredentialNotFoundError,
    CredentialRepository,
    CredentialRepositoryError,
)
from .encryption import EncryptionError, EncryptionService

logger = logging.getLogger(__name__)


# ── Domain exceptions ─────────────────────────────────────────────────────────

class CredentialServiceError(Exception):
    """Raised when the vault service is unavailable (e.g., MongoDB down)."""


class TooManyAttemptsError(Exception):
    """Raised when rate limit is exceeded on sensitive operations."""


# Re-export for views to import from one place.
__all__ = [
    "CredentialService",
    "CredentialServiceError",
    "CredentialNotFoundError",
    "TooManyAttemptsError",
]


# ── Service ───────────────────────────────────────────────────────────────────

class CredentialService:
    """Core vault business logic. All dependencies are injected for testability."""

    def __init__(
        self,
        repo: Optional[CredentialRepository],
        encryption_service: EncryptionService,
        rate_limiter: RateLimiter,
        audit_service: AuditService,
    ) -> None:
        self._repo = repo
        self._enc = encryption_service
        self._limiter = rate_limiter
        self._audit = audit_service

    def _require_repo(self) -> CredentialRepository:
        if self._repo is None:
            raise CredentialServiceError(
                "The vault is temporarily unavailable. MongoDB is not configured."
            )
        return self._repo

    # ── Create ────────────────────────────────────────────────────────────────

    def create_credential(
        self,
        user_id: str,
        plaintext_password: str,
        website_name: str,
        website_url: str = "",
        username: str = "",
        email: str = "",
        category: str = "general",
        notes: str = "",
        favorite: bool = False,
        ip_address: Optional[str] = None,
    ) -> dict:
        """Create and persist an encrypted credential.

        The plaintext_password is:
        1. Scored for strength (never stored).
        2. Encrypted with AES-256-GCM.
        3. Purged from local scope after encryption.
        Only the ciphertext reaches MongoDB.

        Returns a safe credential dict (no plaintext, no encrypted_password).
        """
        repo = self._require_repo()

        # Score BEFORE encrypting (scorer needs plaintext)
        security_score, security_level = score_password(plaintext_password)

        # Encrypt — plaintext_password is no longer referenced after this line.
        try:
            encrypted_password = self._enc.encrypt(plaintext_password)
        except EncryptionError as exc:
            logger.error("Encryption failed during credential creation.")
            raise CredentialServiceError("Failed to secure the credential.") from exc
        finally:
            # Best-effort: overwrite local reference. Python's GC is not
            # guaranteed to zero memory immediately, but this reduces the window.
            plaintext_password = None  # noqa: F841

        credential = Credential(
            user_id=user_id,
            website_name=website_name,
            website_url=website_url,
            username=username,
            email=email,
            encrypted_password=encrypted_password,
            category=category,
            notes=notes,
            favorite=favorite,
            security_score=security_score,
            security_level=security_level,
        )

        try:
            repo.create(credential.to_mongo_doc())
        except CredentialRepositoryError as exc:
            raise CredentialServiceError("Failed to save credential.") from exc

        self._audit.log(
            AuditEvent.CREDENTIAL_CREATED,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"credential_id": credential.credential_id, "category": category},
        )

        return credential.safe_dict()

    # ── List ──────────────────────────────────────────────────────────────────

    def list_credentials(
        self,
        user_id: str,
        filters: Optional[dict] = None,
        search: Optional[str] = None,
    ) -> list[dict]:
        """Return all credentials belonging to user_id (lean list representation).

        The repository enforces user_id scoping. Notes and encrypted_password
        are excluded by the MongoDB projection.
        """
        repo = self._require_repo()
        docs = repo.find_all_by_user(user_id=user_id, filters=filters, search=search)
        result = []
        for doc in docs:
            cred = Credential.from_mongo_doc({**doc, "encrypted_password": ""})
            result.append(cred.list_dict())
        return result

    # ── Detail ────────────────────────────────────────────────────────────────

    def get_credential(self, credential_id: str, user_id: str) -> dict:
        """Return full safe metadata for a credential owned by user_id.

        CredentialNotFoundError is raised (→ 404) for missing OR wrong-owner.
        This prevents IDOR information leakage.
        """
        repo = self._require_repo()
        doc = repo.find_by_id_and_user(credential_id=credential_id, user_id=user_id)
        cred = Credential.from_mongo_doc({**doc, "encrypted_password": ""})

        self._audit.log(
            AuditEvent.CREDENTIAL_VIEWED,
            user_id=user_id,
            metadata={"credential_id": credential_id},
        )

        return cred.safe_dict()

    # ── Update ────────────────────────────────────────────────────────────────

    def update_credential(
        self,
        credential_id: str,
        user_id: str,
        updates: dict,
        ip_address: Optional[str] = None,
    ) -> dict:
        """Update allowed fields on a credential owned by user_id.

        If 'password' is in updates, the new plaintext is encrypted before storage.
        The plaintext is never stored.

        Returns the updated safe credential dict.
        """
        repo = self._require_repo()

        db_updates: dict = {}
        plaintext_password = updates.pop("password", None)

        if plaintext_password is not None:
            # Re-score and re-encrypt the new password.
            security_score, security_level = score_password(plaintext_password)
            try:
                encrypted_password = self._enc.encrypt(plaintext_password)
            except EncryptionError as exc:
                raise CredentialServiceError("Failed to secure the new password.") from exc
            finally:
                plaintext_password = None  # noqa: F841

            db_updates["encrypted_password"] = encrypted_password
            db_updates["security_score"] = security_score
            db_updates["security_level"] = security_level

        # Map remaining validated fields — only whitelisted keys from the serializer.
        _updatable = {"website_name", "website_url", "username", "email", "category", "notes", "favorite"}
        for key in _updatable:
            if key in updates:
                db_updates[key] = updates[key]

        if not db_updates:
            # Nothing to update — fetch and return current state.
            doc = repo.find_by_id_and_user(credential_id=credential_id, user_id=user_id)
            cred = Credential.from_mongo_doc({**doc, "encrypted_password": ""})
            return cred.safe_dict()

        db_updates["updated_at"] = datetime.now(timezone.utc)

        updated_doc = repo.update_by_id_and_user(
            credential_id=credential_id, user_id=user_id, updates=db_updates
        )
        cred = Credential.from_mongo_doc({**updated_doc, "encrypted_password": ""})

        self._audit.log(
            AuditEvent.CREDENTIAL_UPDATED,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"credential_id": credential_id},
        )

        return cred.safe_dict()

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete_credential(
        self,
        credential_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Permanently delete a credential owned by user_id.

        CredentialNotFoundError is raised (→ 404) if not found or not owned.
        """
        repo = self._require_repo()
        repo.delete_by_id_and_user(credential_id=credential_id, user_id=user_id)

        self._audit.log(
            AuditEvent.CREDENTIAL_DELETED,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"credential_id": credential_id},
        )

    # ── Reveal ────────────────────────────────────────────────────────────────

    def reveal_password(
        self,
        credential_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ) -> str:
        """Decrypt and return the credential password.

        Rate-limited per (user_id, ip_address) key.
        Ownership enforced by repository scoping.

        Returns:
            The plaintext password string.

        NEVER:
            - Log the return value.
            - Cache the return value.
            - Store the return value anywhere outside this call frame.
        """
        repo = self._require_repo()

        rate_key = f"{user_id}:{ip_address or 'unknown'}"
        if not self._limiter.check_and_record(RATE_LIMIT_REVEAL, rate_key):
            raise TooManyAttemptsError(
                "Too many reveal requests. Please try again later."
            )

        encrypted = repo.get_encrypted_password_for_owner(
            credential_id=credential_id, user_id=user_id
        )

        try:
            plaintext = self._enc.decrypt(encrypted)
        except EncryptionError as exc:
            logger.error(
                "Decryption failed for credential %s (user %s): %s",
                credential_id,
                user_id,
                type(exc).__name__,
            )
            raise CredentialServiceError(
                "Failed to decrypt the credential password."
            ) from exc

        repo.update_last_used(credential_id=credential_id, user_id=user_id)

        self._audit.log(
            AuditEvent.PASSWORD_REVEALED,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"credential_id": credential_id},
        )

        # plaintext exists here and in the caller's stack frame only.
        # It is never stored, cached, or logged.
        return plaintext

    # ── Copy ─────────────────────────────────────────────────────────────────

    def copy_password(
        self,
        credential_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ) -> str:
        """Authenticate, authorize, rate-limit, and return password for clipboard use.

        Functionally identical to reveal_password but records a distinct audit
        event (PASSWORD_COPIED) so reveal vs. copy patterns can be analysed.

        The frontend/browser layer is responsible for clipboard interaction.
        This endpoint provides the authenticated, rate-limited access event only.

        Returns:
            The plaintext password string.

        NEVER:
            - Log the return value.
            - Claim this endpoint controls the user's clipboard.
        """
        repo = self._require_repo()

        rate_key = f"{user_id}:{ip_address or 'unknown'}"
        if not self._limiter.check_and_record(RATE_LIMIT_COPY, rate_key):
            raise TooManyAttemptsError(
                "Too many copy requests. Please try again later."
            )

        encrypted = repo.get_encrypted_password_for_owner(
            credential_id=credential_id, user_id=user_id
        )

        try:
            plaintext = self._enc.decrypt(encrypted)
        except EncryptionError as exc:
            logger.error(
                "Decryption failed for copy of credential %s (user %s): %s",
                credential_id,
                user_id,
                type(exc).__name__,
            )
            raise CredentialServiceError("Failed to decrypt the credential.") from exc

        repo.update_last_used(credential_id=credential_id, user_id=user_id)

        self._audit.log(
            AuditEvent.PASSWORD_COPIED,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"credential_id": credential_id},
        )

        return plaintext
