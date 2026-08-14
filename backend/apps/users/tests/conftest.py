"""Shared test fixtures for the users app test suite.

All heavy dependencies (MongoDB repository, audit service) are mocked so tests
run without any external services. The TokenService is real and uses Django's
test settings (DJANGO_SECRET_KEY = 'unsafe-development-key-replace-me').

Argon2id parameters in sample_user_doc are intentionally set to minimal values
(time_cost=1, memory_cost=8192) to keep unit tests fast.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from rest_framework.test import APIClient

from apps.audit.services.audit import AuditService
from apps.users.services.authentication import TokenService
from apps.users.services.rate_limiting import NullRateLimiter
from apps.users.services.users import UserService


@pytest.fixture
def api_client():
    """DRF test client — no credentials."""
    return APIClient()


@pytest.fixture
def token_service():
    """Real TokenService using the development Django secret key."""
    return TokenService()


@pytest.fixture
def null_rate_limiter():
    """NullRateLimiter — allows all requests without Redis."""
    return NullRateLimiter()


@pytest.fixture
def mock_audit():
    """Mock AuditService — records calls without logging or persisting."""
    return MagicMock(spec=AuditService)


@pytest.fixture
def mock_user_repo():
    """Mock UserRepository pre-configured with sensible defaults."""
    repo = MagicMock()
    repo.find_by_email.return_value = None        # no user by default
    repo.find_by_user_id.return_value = None
    repo.create_user.return_value = None
    repo.update_last_login.return_value = None
    repo.store_refresh_token.return_value = None
    repo.revoke_refresh_token.return_value = None
    repo.is_refresh_token_valid.return_value = True
    return repo


@pytest.fixture
def sample_user_doc():
    """A realistic user document as stored in MongoDB (with Argon2id hash)."""
    from argon2 import PasswordHasher

    # Minimal parameters for speed — never use these in production
    ph = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    return {
        "user_id": str(uuid.uuid4()),
        "email": "test@example.com",
        "full_name": "Test User",
        "password_hash": ph.hash("ValidPass1!"),
        "email_verified": False,
        "account_status": "active",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_login_at": None,
    }


@pytest.fixture
def disabled_user_doc(sample_user_doc):
    """A user document with account_status = 'disabled'."""
    return {**sample_user_doc, "account_status": "disabled"}


@pytest.fixture
def user_service(mock_user_repo, token_service, null_rate_limiter, mock_audit):
    """Fully wired UserService with mocked repository and audit."""
    return UserService(
        user_repo=mock_user_repo,
        token_service=token_service,
        rate_limiter=null_rate_limiter,
        audit_service=mock_audit,
    )
