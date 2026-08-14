"""Domain models for the users app.

Pure Python dataclasses — NOT Django ORM models.
User data is persisted in MongoDB through the UserRepository.
No ORM, no migrations, no Django User model.

NEVER include plaintext passwords in any model field.
Only password_hash (Argon2id output) is stored.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class User:
    """Represents a KeyVaultAI user account.

    password_hash stores an Argon2id hash — never a plaintext password.
    """

    email: str
    full_name: str
    password_hash: str  # Argon2id hash; NEVER plaintext

    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    email_verified: bool = False
    account_status: str = "active"  # active | disabled | pending_verification
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    last_login_at: Optional[datetime] = None

    def to_mongo_doc(self) -> dict:
        """Serialize for MongoDB insertion.

        Includes password_hash (Argon2id) — do not return this to clients.
        """
        return {
            "user_id": self.user_id,
            "email": self.email,
            "full_name": self.full_name,
            "password_hash": self.password_hash,
            "email_verified": self.email_verified,
            "account_status": self.account_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login_at": self.last_login_at,
        }

    def safe_dict(self) -> dict:
        """Return a representation safe for API responses.

        Excludes: password_hash, and any other secret fields.
        """
        return {
            "user_id": self.user_id,
            "email": self.email,
            "full_name": self.full_name,
            "email_verified": self.email_verified,
            "account_status": self.account_status,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class RefreshToken:
    """Tracks an issued refresh token JTI for revocation support."""

    jti: str
    user_id: str
    expires_at: datetime
    created_at: datetime = field(default_factory=_utcnow)
    revoked: bool = False

    def to_mongo_doc(self) -> dict:
        return {
            "jti": self.jti,
            "user_id": self.user_id,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "revoked": self.revoked,
        }
