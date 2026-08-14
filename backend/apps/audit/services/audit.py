"""Audit logging service.

Records safe metadata about security-relevant events to the Python logger
and optionally to a MongoDB 'audit_events' collection.

NEVER stores:
- plaintext passwords
- password hashes
- JWT tokens or refresh tokens
- encryption keys
- full email addresses (use email_prefix — first 3 chars only)

All fields written to the audit record must be reviewed for sensitive content.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class AuditEvent:
    """Enum-like constants for audit event types."""

    # Authentication events (Milestone 2)
    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"

    # Vault events (Milestone 3)
    CREDENTIAL_CREATED = "CREDENTIAL_CREATED"
    CREDENTIAL_UPDATED = "CREDENTIAL_UPDATED"
    CREDENTIAL_DELETED = "CREDENTIAL_DELETED"
    CREDENTIAL_VIEWED = "CREDENTIAL_VIEWED"
    PASSWORD_REVEALED = "PASSWORD_REVEALED"
    PASSWORD_COPIED = "PASSWORD_COPIED"



class AuditService:
    """Writes audit events to the application logger and optionally to MongoDB.

    Use get_audit_service() factory to obtain an instance.
    """

    def __init__(self, db=None):
        """
        Args:
            db: MongoDB database handle (or None if MongoDB is not available).
                When None, events are only written to the logger.
        """
        self._db = db

    def log(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        email_prefix: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """Write an audit event.

        Args:
            event_type:    One of the AuditEvent constants.
            user_id:       The user's UUID — safe to log.
            email_prefix:  First 3 characters of the email (e.g. "tes" for
                           "test@example.com"). Never log the full email.
            ip_address:    Client IP address.
            metadata:      Additional context dict. Must not contain secrets.
        """
        record = {
            "event": event_type,
            "user_id": user_id,
            "email_prefix": email_prefix,
            "ip_address": ip_address,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            record["metadata"] = metadata

        logger.info(
            "AUDIT event=%s user_id=%s ip=%s",
            event_type,
            user_id,
            ip_address,
        )

        if self._db is not None:
            try:
                doc = {k: v for k, v in record.items() if v is not None}
                self._db["audit_events"].insert_one(doc)
                doc.pop("_id", None)
            except Exception:
                logger.warning(
                    "Failed to persist audit event to MongoDB (event logged above)."
                )


def get_audit_service(db=None) -> AuditService:
    """Factory — returns an AuditService backed by the given database handle."""
    return AuditService(db=db)
