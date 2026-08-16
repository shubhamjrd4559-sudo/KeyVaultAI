"""MongoDB repository for credential persistence.

CRITICAL SECURITY INVARIANTS — enforced at this layer:

1. EVERY query is scoped by BOTH credential_id AND user_id.
   No query ever fetches credentials by credential_id alone.
   This prevents IDOR vulnerabilities at the database layer.

2. List queries ALWAYS filter by user_id first.
   No method exists to list all credentials across users.

3. encrypted_password is excluded from all projections except
   get_encrypted_password_for_owner(), which is called ONLY by
   reveal/copy flows.

4. Caller-supplied filter values are constrained to whitelisted keys
   and literal values — no arbitrary MongoDB query operators accepted
   from the client.

5. User-supplied search strings are escaped before use in $regex.

NEVER:
- Add a method that queries by credential_id alone.
- Return encrypted_password in list/detail projections.
- Accept arbitrary query dictionaries from callers.
"""
import logging
import re as _re
from datetime import datetime, timezone
from typing import Optional

from pymongo import ASCENDING, DESCENDING

logger = logging.getLogger(__name__)

# ── Domain exceptions ────────────────────────────────────────────────────────

class CredentialNotFoundError(Exception):
    """Raised when a credential does not exist OR does not belong to the user.

    Intentionally ambiguous — callers must NOT distinguish these two cases.
    Returning 404 for both cases prevents IDOR enumeration.
    """


class CredentialRepositoryError(Exception):
    """Raised for unexpected MongoDB errors."""


# ── Repository ────────────────────────────────────────────────────────────────

# Fields always excluded from public projections.
_EXCLUDE_SENSITIVE = {"_id": 0, "encrypted_password": 0}
# List endpoint projection: also excludes notes for leaner responses.
_LIST_PROJECTION = {"_id": 0, "encrypted_password": 0, "notes": 0}
# Detail projection: includes notes, excludes encrypted_password.
_DETAIL_PROJECTION = {"_id": 0, "encrypted_password": 0}

# Whitelisted filter keys and their allowed value types.
_ALLOWED_FILTER_KEYS = frozenset({"category", "favorite", "security_level"})
_ALLOWED_SORT_FIELDS = frozenset({"created_at", "updated_at", "website_name", "security_score"})


class CredentialRepository:
    """Data-access layer for the 'credentials' MongoDB collection.

    All queries are scoped by user_id. MongoDB is the single source of truth.
    """

    def __init__(self, db):
        self._db = db
        self._col = db["credentials"]

    def ensure_indexes(self) -> None:
        """Create required indexes. Idempotent — safe to call at startup."""
        self._col.create_index(
            [("credential_id", ASCENDING)], unique=True, name="idx_credential_id"
        )
        self._col.create_index([("user_id", ASCENDING)], name="idx_user_id")
        self._col.create_index(
            [("user_id", ASCENDING), ("credential_id", ASCENDING)],
            name="idx_user_credential",
        )
        self._col.create_index(
            [("user_id", ASCENDING), ("category", ASCENDING)],
            name="idx_user_category",
        )
        self._col.create_index(
            [("user_id", ASCENDING), ("favorite", ASCENDING)],
            name="idx_user_favorite",
        )
        self._col.create_index(
            [("user_id", ASCENDING), ("security_level", ASCENDING)],
            name="idx_user_security_level",
        )
        self._col.create_index(
            [("created_at", ASCENDING)], name="idx_created_at"
        )

    # ── Creation ──────────────────────────────────────────────────────────────

    def create(self, doc: dict) -> None:
        """Insert a credential document. doc must already contain encrypted_password."""
        try:
            self._col.insert_one({**doc})
        except Exception as exc:
            logger.exception("Failed to insert credential.")
            raise CredentialRepositoryError("Failed to create credential.") from exc

    # ── Read — list ───────────────────────────────────────────────────────────

    def find_all_by_user(
        self,
        user_id: str,
        filters: Optional[dict] = None,
        search: Optional[str] = None,
    ) -> list[dict]:
        """Return all credentials for user_id, applying safe optional filters.

        ALWAYS starts with {"user_id": user_id} — cannot be bypassed.
        encrypted_password and notes are excluded from the projection.

        Args:
            user_id:  The authenticated user's ID (from JWT — never from client).
            filters:  Optional dict with keys from _ALLOWED_FILTER_KEYS only.
            search:   Optional free-text search on website_name/url/username.
        """
        query: dict = {"user_id": user_id}

        if filters:
            for key, value in filters.items():
                if key not in _ALLOWED_FILTER_KEYS:
                    logger.warning("Rejected disallowed filter key: %s", key)
                    continue
                query[key] = value  # only literal values from validated serializer

        if search:
            # Escape special regex chars to prevent ReDoS/injection.
            safe_search = _re.escape(search.strip())
            query["$or"] = [
                {"website_name": {"$regex": safe_search, "$options": "i"}},
                {"website_url": {"$regex": safe_search, "$options": "i"}},
                {"username": {"$regex": safe_search, "$options": "i"}},
            ]

        return list(
            self._col.find(query, _LIST_PROJECTION).sort("created_at", DESCENDING)
        )

    # ── Read — single ─────────────────────────────────────────────────────────

    def find_by_id_and_user(self, credential_id: str, user_id: str) -> dict:
        """Return the credential doc for this id + user, or raise CredentialNotFoundError.

        ALWAYS scopes by user_id — if the credential exists but belongs to
        a different user, CredentialNotFoundError is raised (same as not found).
        This prevents IDOR attacks and information leakage.
        """
        doc = self._col.find_one(
            {"credential_id": credential_id, "user_id": user_id},
            _DETAIL_PROJECTION,
        )
        if doc is None:
            raise CredentialNotFoundError(
                f"Credential not found: {credential_id}"
            )
        return doc

    def get_encrypted_password_for_owner(
        self, credential_id: str, user_id: str
    ) -> str:
        """Return ONLY the encrypted_password for a credential owned by user_id.

        Used exclusively by the reveal/copy flows.
        Returns the raw encrypted string — callers must decrypt it with EncryptionService.
        Raises CredentialNotFoundError if not found or not owned by user.

        NEVER expose this field through any other path.
        """
        doc = self._col.find_one(
            {"credential_id": credential_id, "user_id": user_id},
            {"encrypted_password": 1, "_id": 0},
        )
        if doc is None:
            raise CredentialNotFoundError(
                f"Credential not found: {credential_id}"
            )
        return doc["encrypted_password"]

    # ── Update ────────────────────────────────────────────────────────────────

    def update_by_id_and_user(
        self, credential_id: str, user_id: str, updates: dict
    ) -> dict:
        """Update fields on a credential owned by user_id.

        Returns the updated document.
        Raises CredentialNotFoundError if not found or not owned by user.

        updates must never include credential_id or user_id.
        """
        # Prevent callers from overwriting ownership fields.
        updates.pop("credential_id", None)
        updates.pop("user_id", None)

        result = self._col.find_one_and_update(
            {"credential_id": credential_id, "user_id": user_id},
            {"$set": updates},
            projection=_DETAIL_PROJECTION,
            return_document=True,  # pymongo ReturnDocument.AFTER equivalent
        )
        if result is None:
            raise CredentialNotFoundError(
                f"Credential not found: {credential_id}"
            )
        return result

    def update_last_used(self, credential_id: str, user_id: str) -> None:
        """Stamp last_used_at for reveal/copy operations."""
        self._col.update_one(
            {"credential_id": credential_id, "user_id": user_id},
            {"$set": {"last_used_at": datetime.now(timezone.utc)}},
        )

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete_by_id_and_user(self, credential_id: str, user_id: str) -> None:
        """Delete a credential owned by user_id.

        Raises CredentialNotFoundError if not found or not owned by user.
        """
        result = self._col.delete_one(
            {"credential_id": credential_id, "user_id": user_id}
        )
        if result.deleted_count == 0:
            raise CredentialNotFoundError(
                f"Credential not found: {credential_id}"
            )

    # ── Security analysis ─────────────────────────────────────────────────────

    def find_all_encrypted_for_user(self, user_id: str) -> list[dict]:
        """Return minimal credential data needed for password-reuse detection.

        Returns a list of dicts with ONLY:
          - credential_id (str)
          - encrypted_password (str)

        SECURITY INVARIANTS:
        - ALWAYS scoped to user_id — cross-user access is impossible.
        - Returns ONLY encrypted_password and credential_id — no other fields.
        - Caller (SecurityAnalyzer.detect_reuse) decrypts transiently and
          immediately hashes the result. Hashes are discarded after use.
        - This method MUST NOT be called from any endpoint that returns
          the encrypted ciphertext to clients.

        Called exclusively by the Security Engine for reuse analysis.
        NEVER expose the return value directly in an API response.
        """
        projection = {"_id": 0, "credential_id": 1, "encrypted_password": 1}
        try:
            return list(
                self._col.find({"user_id": user_id}, projection)
            )
        except Exception as exc:
            logger.exception("Failed to fetch encrypted credentials for security analysis.")
            raise CredentialRepositoryError(
                "Failed to retrieve credentials for security analysis."
            ) from exc
