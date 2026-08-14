"""Domain model for vault credentials.

Pure Python dataclasses — NOT Django ORM models.
Credential data is persisted in MongoDB through CredentialRepository.

Security invariants enforced here:
- encrypted_password is NEVER the plaintext; it stores the AES-256-GCM ciphertext.
- safe_dict() and list_dict() NEVER include encrypted_password.
- user_id is always set from the authenticated JWT, never from client input.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Allowed categories ────────────────────────────────────────────────────────
VALID_CATEGORIES = frozenset(
    {"general", "social", "finance", "work", "shopping", "entertainment", "education", "other"}
)

# ── Security level classification ─────────────────────────────────────────────
SECURITY_LEVELS = ("weak", "fair", "strong", "very_strong")


def score_password(password: str) -> tuple[int, str]:
    """Compute a deterministic security score and level label.

    Returns (score: 0–100, level: 'weak' | 'fair' | 'strong' | 'very_strong').
    This is a basic heuristic — advanced ML-based scoring is planned for Milestone 6.

    NEVER called with an already-encrypted value — always receives the plaintext.
    """
    score = 0

    # Length contribution (up to 40 points)
    length = len(password)
    if length >= 8:
        score += 10
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length >= 20:
        score += 10

    # Character diversity (up to 40 points)
    if any(c.isupper() for c in password):
        score += 10
    if any(c.islower() for c in password):
        score += 10
    if any(c.isdigit() for c in password):
        score += 10
    if any(c in r"!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        score += 10

    # Character variety bonus (up to 20 points)
    unique_count = len(set(password))
    if unique_count >= 8:
        score += 10
    if unique_count >= 14:
        score += 10

    score = min(score, 100)

    if score >= 80:
        level = "very_strong"
    elif score >= 60:
        level = "strong"
    elif score >= 40:
        level = "fair"
    else:
        level = "weak"

    return score, level


@dataclass
class Credential:
    """Represents a stored credential.

    encrypted_password stores AES-256-GCM ciphertext — never plaintext.
    user_id is always derived from the authenticated JWT — never from client input.
    """

    user_id: str
    website_name: str
    encrypted_password: str  # AES-256-GCM ciphertext; NEVER plaintext

    credential_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    website_url: str = ""
    username: str = ""
    email: str = ""
    category: str = "general"
    notes: str = ""
    favorite: bool = False
    security_score: int = 0
    security_level: str = "weak"
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)
    last_used_at: Optional[datetime] = None

    def to_mongo_doc(self) -> dict:
        """Serialize for MongoDB insertion.

        Includes encrypted_password — do NOT return this to clients.
        """
        return {
            "credential_id": self.credential_id,
            "user_id": self.user_id,
            "website_name": self.website_name,
            "website_url": self.website_url,
            "username": self.username,
            "email": self.email,
            "encrypted_password": self.encrypted_password,
            "category": self.category,
            "notes": self.notes,
            "favorite": self.favorite,
            "security_score": self.security_score,
            "security_level": self.security_level,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_used_at": self.last_used_at,
        }

    def safe_dict(self) -> dict:
        """Full detail representation — safe for API responses.

        EXCLUDES: encrypted_password. Never add it back.
        """
        return {
            "credential_id": self.credential_id,
            "website_name": self.website_name,
            "website_url": self.website_url,
            "username": self.username,
            "email": self.email,
            "category": self.category,
            "notes": self.notes,
            "favorite": self.favorite,
            "security_score": self.security_score,
            "security_level": self.security_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }

    def list_dict(self) -> dict:
        """Lean representation for list endpoints — excludes notes.

        EXCLUDES: encrypted_password, notes. Never add encrypted_password.
        """
        return {
            "credential_id": self.credential_id,
            "website_name": self.website_name,
            "website_url": self.website_url,
            "username": self.username,
            "email": self.email,
            "category": self.category,
            "favorite": self.favorite,
            "security_score": self.security_score,
            "security_level": self.security_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_mongo_doc(cls, doc: dict) -> "Credential":
        """Reconstruct from a MongoDB document."""
        return cls(
            credential_id=doc["credential_id"],
            user_id=doc["user_id"],
            website_name=doc["website_name"],
            website_url=doc.get("website_url", ""),
            username=doc.get("username", ""),
            email=doc.get("email", ""),
            encrypted_password=doc.get("encrypted_password", ""),
            category=doc.get("category", "general"),
            notes=doc.get("notes", ""),
            favorite=doc.get("favorite", False),
            security_score=doc.get("security_score", 0),
            security_level=doc.get("security_level", "weak"),
            created_at=doc.get("created_at", _utcnow()),
            updated_at=doc.get("updated_at", _utcnow()),
            last_used_at=doc.get("last_used_at"),
        )
