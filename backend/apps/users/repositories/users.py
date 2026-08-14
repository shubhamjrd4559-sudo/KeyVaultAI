"""MongoDB repository for user and refresh-token persistence.

Responsibilities:
- All MongoDB CRUD for the 'users' and 'refresh_tokens' collections.
- Email normalization before storage and lookup.
- Translates pymongo DuplicateKeyError into domain exceptions.
- Never leaks MongoDB internals to callers.

Callers must catch UserAlreadyExistsError and UserNotFoundError.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

logger = logging.getLogger(__name__)


# ── Domain exceptions ────────────────────────────────────────────────────────

class UserAlreadyExistsError(Exception):
    """A user with the supplied email already exists in the database."""


class UserNotFoundError(Exception):
    """No user matched the supplied identifier."""


# ── Repository ───────────────────────────────────────────────────────────────

class UserRepository:
    """Data-access layer for users and refresh tokens in MongoDB.

    Requires a live MongoDB database handle. Pass a mock in tests.
    """

    def __init__(self, db):
        self._db = db
        self._users = db["users"]
        self._tokens = db["refresh_tokens"]

    def ensure_indexes(self) -> None:
        """Create required collection indexes. Idempotent — safe to call at startup."""
        self._users.create_index(
            [("email", ASCENDING)], unique=True, name="idx_email_unique"
        )
        self._users.create_index(
            [("user_id", ASCENDING)], unique=True, name="idx_user_id_unique"
        )
        self._tokens.create_index(
            [("jti", ASCENDING)], unique=True, name="idx_jti_unique"
        )
        self._tokens.create_index(
            [("user_id", ASCENDING)], name="idx_token_user_id"
        )
        # MongoDB TTL index — automatically deletes expired token documents.
        self._tokens.create_index(
            [("expires_at", ASCENDING)],
            expireAfterSeconds=0,
            name="idx_token_ttl",
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def normalize_email(email: str) -> str:
        return email.lower().strip()

    # ── User CRUD ────────────────────────────────────────────────────────────

    def find_by_email(self, email: str) -> Optional[dict]:
        """Return the user document for the given email, or None."""
        return self._users.find_one(
            {"email": self.normalize_email(email)},
            {"_id": 0},  # exclude internal Mongo _id from results
        )

    def find_by_user_id(self, user_id: str) -> Optional[dict]:
        """Return the user document for the given user_id, or None."""
        return self._users.find_one({"user_id": user_id}, {"_id": 0})

    def create_user(self, user_doc: dict) -> None:
        """Insert a new user document.

        Raises:
            UserAlreadyExistsError: if a user with the same email already exists.
        """
        doc = {**user_doc, "email": self.normalize_email(user_doc["email"])}
        try:
            self._users.insert_one(doc)
        except DuplicateKeyError:
            raise UserAlreadyExistsError(
                "A user with this email already exists."
            )

    def update_last_login(self, user_id: str) -> None:
        """Stamp last_login_at and updated_at on the user document."""
        now = datetime.now(timezone.utc)
        self._users.update_one(
            {"user_id": user_id},
            {"$set": {"last_login_at": now, "updated_at": now}},
        )

    # ── Refresh token management ──────────────────────────────────────────────

    def store_refresh_token(
        self, jti: str, user_id: str, expires_at: datetime
    ) -> None:
        """Persist a refresh token JTI for later validation and revocation."""
        self._tokens.insert_one(
            {
                "jti": jti,
                "user_id": user_id,
                "expires_at": expires_at,
                "created_at": datetime.now(timezone.utc),
                "revoked": False,
            }
        )

    def revoke_refresh_token(self, jti: str) -> None:
        """Mark a specific refresh token as revoked."""
        self._tokens.update_one({"jti": jti}, {"$set": {"revoked": True}})

    def revoke_all_user_tokens(self, user_id: str) -> None:
        """Revoke ALL refresh tokens for a user (force full logout)."""
        self._tokens.update_many(
            {"user_id": user_id}, {"$set": {"revoked": True}}
        )

    def is_refresh_token_valid(self, jti: str) -> bool:
        """Return True if the token exists, is not revoked, and has not expired."""
        doc = self._tokens.find_one({"jti": jti})
        if doc is None:
            return False
        if doc.get("revoked", False):
            return False
        expires_at = doc.get("expires_at")
        if expires_at and expires_at < datetime.now(timezone.utc):
            return False
        return True
