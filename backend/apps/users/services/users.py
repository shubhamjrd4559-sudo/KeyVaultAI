"""User business-logic service.

Orchestrates the complete registration and authentication flows:
  Validation → Repository → Hashing → Tokens → Audit

Security rules enforced here:
- Argon2id password hashing (NEVER plaintext storage).
- Constant-time password comparison to resist timing attacks.
- Email normalization before all lookups.
- Ambiguous error messages to resist user enumeration.
- Rate limiting checked before any database access.

NEVER:
- Log plaintext passwords or password hashes.
- Return password_hash to callers.
- Expose MongoDB internals.
- Differentiate "email not found" from "wrong password" in responses.
"""
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from apps.audit.services.audit import AuditEvent, AuditService
from ..models import User
from ..repositories.users import UserAlreadyExistsError, UserRepository
from .authentication import TokenService
from .rate_limiting import (
    RATE_LIMIT_LOGIN,
    RATE_LIMIT_REFRESH,
    RATE_LIMIT_REGISTER,
    RateLimiter,
)

logger = logging.getLogger(__name__)

# ── Argon2id configuration (OWASP Argon2id recommended minimum) ───────────────
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
    encoding="utf-8",
)

# Used in timing-safe dummy verify when the user is not found.
# Pre-computed so we don't hash on every failed login attempt.
_DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4"
    "$AAAAAAAAAAAAAAAAAAAAAA"
    "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_MIN_PASSWORD_LEN = 10


# ── Domain exceptions ─────────────────────────────────────────────────────────

class AuthenticationError(Exception):
    """Raised for invalid credentials.

    The message must NEVER reveal whether the email exists or the password
    was wrong — always use a generic message to prevent user enumeration.
    """


class AccountDisabledError(Exception):
    """Raised when a disabled account attempts to log in."""


class RegistrationError(Exception):
    """Raised for invalid or conflicting registration data."""


class TooManyAttemptsError(Exception):
    """Raised when rate limit is exceeded."""


# ── Service ───────────────────────────────────────────────────────────────────

class UserService:
    """Core authentication business logic.

    Dependencies are injected so the service is fully testable with mocks.
    """

    def __init__(
        self,
        user_repo: Optional[UserRepository],
        token_service: TokenService,
        rate_limiter: RateLimiter,
        audit_service: AuditService,
    ) -> None:
        self._repo = user_repo
        self._tokens = token_service
        self._limiter = rate_limiter
        self._audit = audit_service

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        email: str,
        password: str,
        full_name: str,
        ip_address: Optional[str] = None,
    ) -> dict:
        """Register a new user. Returns a safe user dict (no password_hash)."""
        if self._repo is None:
            raise RegistrationError(
                "Registration is temporarily unavailable. Contact an administrator."
            )

        if not self._limiter.check_and_record(
            RATE_LIMIT_REGISTER, ip_address or "unknown"
        ):
            raise TooManyAttemptsError(
                "Too many registration attempts. Please try again later."
            )

        norm_email = _normalize_email(email)
        _validate_email(norm_email)
        _validate_password(password)
        _validate_full_name(full_name)

        # Duplicate check — intentionally vague message to the caller
        existing = self._repo.find_by_email(norm_email)
        if existing is not None:
            raise RegistrationError(
                "Unable to complete registration. Please check your details."
            )

        # Hash with Argon2id — NEVER store plaintext
        password_hash = _HASHER.hash(password)

        user = User(
            email=norm_email,
            full_name=full_name.strip(),
            password_hash=password_hash,
        )
        self._repo.create_user(user.to_mongo_doc())

        self._audit.log(
            AuditEvent.REGISTER,
            user_id=user.user_id,
            email_prefix=norm_email[:3],
            ip_address=ip_address,
        )

        return user.safe_dict()

    # ── Login ─────────────────────────────────────────────────────────────────

    def login(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> dict:
        """Authenticate and return JWT access + refresh tokens."""
        if self._repo is None:
            raise AuthenticationError("Invalid credentials.")

        # Rate limit BEFORE touching the database
        if not self._limiter.check_and_record(
            RATE_LIMIT_LOGIN, ip_address or "unknown"
        ):
            raise TooManyAttemptsError(
                "Too many login attempts. Please try again later."
            )

        norm_email = _normalize_email(email)
        user_doc = self._repo.find_by_email(norm_email)

        # Always run the hash verify — even when user is not found — to resist
        # timing-based user enumeration.
        stored_hash = (
            user_doc["password_hash"] if user_doc else _DUMMY_HASH
        )
        try:
            _HASHER.verify(stored_hash, password)
            password_ok = True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            password_ok = False

        if not user_doc or not password_ok:
            self._audit.log(
                AuditEvent.LOGIN_FAILED,
                email_prefix=norm_email[:3],
                ip_address=ip_address,
            )
            # Intentionally ambiguous — do not reveal which field failed
            raise AuthenticationError("Invalid credentials.")

        if user_doc.get("account_status") == "disabled":
            self._audit.log(
                AuditEvent.ACCOUNT_DISABLED,
                user_id=user_doc.get("user_id"),
                ip_address=ip_address,
            )
            raise AccountDisabledError("This account has been disabled.")

        user_id = user_doc["user_id"]

        access_token = self._tokens.generate_access_token(user_id, norm_email)
        refresh_token, jti, expires_at = self._tokens.generate_refresh_token(
            user_id
        )

        self._repo.store_refresh_token(jti, user_id, expires_at)
        self._repo.update_last_login(user_id)

        self._audit.log(
            AuditEvent.LOGIN,
            user_id=user_id,
            email_prefix=norm_email[:3],
            ip_address=ip_address,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
        }

    # ── Logout ────────────────────────────────────────────────────────────────

    def logout(
        self,
        refresh_token: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Revoke the refresh token. Always audits, even on malformed tokens."""
        if self._repo is not None:
            try:
                payload = self._tokens.decode_refresh_token(refresh_token)
                jti = payload.get("jti")
                if jti:
                    self._repo.revoke_refresh_token(jti)
            except Exception:
                # Malformed or expired token — nothing to revoke; proceed to audit
                pass

        self._audit.log(
            AuditEvent.LOGOUT,
            user_id=user_id,
            ip_address=ip_address,
        )

    # ── Token refresh ─────────────────────────────────────────────────────────

    def refresh_tokens(
        self,
        refresh_token: str,
        ip_address: Optional[str] = None,
    ) -> dict:
        """Rotate: validate old refresh token, issue new access + refresh pair."""
        import jwt as _jwt

        if self._repo is None:
            raise AuthenticationError("Invalid refresh token.")

        if not self._limiter.check_and_record(
            RATE_LIMIT_REFRESH, ip_address or "unknown"
        ):
            raise TooManyAttemptsError(
                "Too many refresh attempts. Please try again later."
            )

        try:
            payload = self._tokens.decode_refresh_token(refresh_token)
        except _jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired.")
        except _jwt.PyJWTError:
            raise AuthenticationError("Invalid refresh token.")

        jti = payload.get("jti")
        user_id = payload.get("sub")

        if not self._repo.is_refresh_token_valid(jti):
            raise AuthenticationError(
                "Refresh token has been revoked or is invalid."
            )

        user_doc = self._repo.find_by_user_id(user_id)
        if not user_doc or user_doc.get("account_status") == "disabled":
            raise AuthenticationError("Invalid refresh token.")

        # Rotation: revoke old token, issue new pair
        self._repo.revoke_refresh_token(jti)
        new_access = self._tokens.generate_access_token(
            user_id, user_doc["email"]
        )
        new_refresh, new_jti, new_expires = self._tokens.generate_refresh_token(
            user_id
        )
        self._repo.store_refresh_token(new_jti, user_id, new_expires)

        self._audit.log(
            AuditEvent.TOKEN_REFRESH,
            user_id=user_id,
            ip_address=ip_address,
        )

        return {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token_type": "Bearer",
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_email(email: str) -> str:
    return email.lower().strip()


def _validate_email(email: str) -> None:
    if not _EMAIL_RE.match(email):
        raise RegistrationError("Invalid email address format.")


def _validate_password(password: str) -> None:
    if len(password) < _MIN_PASSWORD_LEN:
        raise RegistrationError(
            f"Password must be at least {_MIN_PASSWORD_LEN} characters."
        )
    checks = [
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password),
    ]
    if not all(checks):
        raise RegistrationError(
            "Password must contain at least one uppercase letter, one lowercase "
            "letter, one digit, and one special character."
        )


def _validate_full_name(full_name: str) -> None:
    if not full_name or not full_name.strip():
        raise RegistrationError("Full name is required.")
    if len(full_name.strip()) < 2:
        raise RegistrationError("Full name must be at least 2 characters.")
