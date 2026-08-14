"""Tests — Security (tests 14–16).

14. User identity cannot be spoofed (request.user.user_id comes from JWT, not body).
15. Audit events are created for REGISTER, LOGIN, LOGOUT.
16. Rate-limit abstraction behaviour:
    - NullRateLimiter always allows.
    - RedisRateLimiter blocks after limit exceeded.
"""
import uuid
from unittest.mock import MagicMock, patch, call

import pytest
from rest_framework.test import APIClient

from apps.audit.services.audit import AuditEvent
from apps.users.authentication import AuthenticatedUser
from apps.users.services.rate_limiting import (
    NullRateLimiter,
    RATE_LIMIT_LOGIN,
    RATE_LIMIT_REGISTER,
    RedisRateLimiter,
)
from apps.users.services.users import (
    AuthenticationError,
    TooManyAttemptsError,
    UserService,
)


# ── 14. User identity cannot be spoofed ───────────────────────────────────────

@pytest.mark.django_db
def test_logout_uses_user_id_from_jwt_not_from_body(api_client, token_service):
    """Logout must use request.user.user_id (from JWT), NOT any user_id in the request body.

    Demonstrates that a client cannot spoof another user's identity by
    supplying a different user_id in the request payload.
    """
    legitimate_user_id = str(uuid.uuid4())
    attacker_user_id = str(uuid.uuid4())

    access_token = token_service.generate_access_token(
        legitimate_user_id, "legit@example.com"
    )

    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_factory.return_value = mock_svc

        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        api_client.post(
            "/api/v1/auth/logout/",
            # Attacker tries to supply a different user_id in the body
            {"refresh_token": "some.token", "user_id": attacker_user_id},
            format="json",
        )

    # The service must have been called with the LEGITIMATE user_id from the JWT
    call_kwargs = mock_svc.logout.call_args
    actual_user_id = call_kwargs.kwargs.get("user_id") or call_kwargs.args[1]
    assert actual_user_id == legitimate_user_id, (
        f"Expected user_id={legitimate_user_id!r} from JWT, "
        f"but got {actual_user_id!r} — identity spoofing not prevented!"
    )


def test_authenticated_user_is_always_from_token():
    """AuthenticatedUser carries only the data from the verified JWT payload."""
    user = AuthenticatedUser(user_id="uuid-from-jwt", email="from@jwt.com")

    assert user.user_id == "uuid-from-jwt"
    assert user.email == "from@jwt.com"
    assert user.is_authenticated is True


# ── 15. Audit event creation ──────────────────────────────────────────────────

def test_register_creates_audit_event(user_service, mock_user_repo, mock_audit):
    """Registration triggers an AUDIT REGISTER event."""
    mock_user_repo.find_by_email.return_value = None

    user_service.register(
        email="audit@example.com",
        password="SecurePass1!",
        full_name="Audit User",
    )

    mock_audit.log.assert_called_once()
    call_kwargs = mock_audit.log.call_args
    event_type = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("event_type")
    assert event_type == AuditEvent.REGISTER


def test_successful_login_creates_audit_event(
    user_service, mock_user_repo, mock_audit, sample_user_doc
):
    """Successful login triggers an AUDIT LOGIN event."""
    mock_user_repo.find_by_email.return_value = sample_user_doc

    user_service.login(email="test@example.com", password="ValidPass1!")

    # Find the LOGIN call (there may also be LOGIN_FAILED checks)
    calls = mock_audit.log.call_args_list
    event_types = [
        (c.args[0] if c.args else c.kwargs.get("event_type")) for c in calls
    ]
    assert AuditEvent.LOGIN in event_types


def test_failed_login_creates_audit_event(
    user_service, mock_user_repo, mock_audit
):
    """Failed login triggers a LOGIN_FAILED audit event."""
    mock_user_repo.find_by_email.return_value = None  # user not found

    with pytest.raises(AuthenticationError):
        user_service.login(email="nobody@example.com", password="BadPass1!")

    calls = mock_audit.log.call_args_list
    event_types = [
        (c.args[0] if c.args else c.kwargs.get("event_type")) for c in calls
    ]
    assert AuditEvent.LOGIN_FAILED in event_types


def test_logout_creates_audit_event(user_service, mock_user_repo, mock_audit, token_service):
    """Logout triggers an AUDIT LOGOUT event."""
    user_id = str(uuid.uuid4())
    refresh_token, _, _ = token_service.generate_refresh_token(user_id)

    user_service.logout(
        refresh_token=refresh_token,
        user_id=user_id,
    )

    calls = mock_audit.log.call_args_list
    event_types = [
        (c.args[0] if c.args else c.kwargs.get("event_type")) for c in calls
    ]
    assert AuditEvent.LOGOUT in event_types


def test_audit_never_contains_password(user_service, mock_user_repo, mock_audit):
    """No audit call should contain a plaintext password in its arguments."""
    password = "SecurePass1!"
    mock_user_repo.find_by_email.return_value = None

    user_service.register(
        email="safeaudit@example.com",
        password=password,
        full_name="Safe Audit",
    )

    for audit_call in mock_audit.log.call_args_list:
        all_args = str(audit_call)
        assert password not in all_args, (
            "Plaintext password found in an audit.log() call — security defect!"
        )


# ── 16. Rate-limit abstraction behaviour ─────────────────────────────────────

def test_null_rate_limiter_always_allows(null_rate_limiter):
    """NullRateLimiter.check_and_record always returns True."""
    for _ in range(50):
        assert null_rate_limiter.check_and_record(RATE_LIMIT_LOGIN, "any-ip") is True


def test_null_rate_limiter_record_is_noop(null_rate_limiter):
    """NullRateLimiter.record does not raise."""
    null_rate_limiter.record(RATE_LIMIT_REGISTER, "any-ip")  # should not raise


def test_redis_rate_limiter_blocks_when_limit_exceeded():
    """RedisRateLimiter.is_allowed returns False after the limit is reached."""
    mock_redis = MagicMock()
    limiter = RedisRateLimiter(mock_redis)

    # Simulate 10 existing attempts (at the limit for RATE_LIMIT_LOGIN)
    mock_redis.get.return_value = b"10"

    allowed = limiter.is_allowed(RATE_LIMIT_LOGIN, "192.168.1.1")
    assert allowed is False


def test_redis_rate_limiter_allows_below_limit():
    """RedisRateLimiter.is_allowed returns True when count is below the limit."""
    mock_redis = MagicMock()
    limiter = RedisRateLimiter(mock_redis)

    mock_redis.get.return_value = b"5"  # below login limit of 10

    allowed = limiter.is_allowed(RATE_LIMIT_LOGIN, "192.168.1.1")
    assert allowed is True


def test_redis_rate_limiter_record_uses_pipeline():
    """RedisRateLimiter.record uses a pipeline for atomic INCR + EXPIRE."""
    mock_redis = MagicMock()
    mock_pipe = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    limiter = RedisRateLimiter(mock_redis)
    limiter.record(RATE_LIMIT_LOGIN, "192.168.1.1")

    mock_redis.pipeline.assert_called_once()
    mock_pipe.incr.assert_called_once()
    mock_pipe.expire.assert_called_once()
    mock_pipe.execute.assert_called_once()


def test_rate_limiter_blocks_user_service_on_limit(
    mock_user_repo, token_service, mock_audit
):
    """When the rate limiter returns False, UserService raises TooManyAttemptsError."""
    blocking_limiter = MagicMock()
    blocking_limiter.check_and_record.return_value = False

    svc = UserService(
        user_repo=mock_user_repo,
        token_service=token_service,
        rate_limiter=blocking_limiter,
        audit_service=mock_audit,
    )

    with pytest.raises(TooManyAttemptsError):
        svc.login(email="limited@example.com", password="SecurePass1!")


@pytest.mark.django_db
def test_rate_limited_login_returns_429(api_client):
    """POST /api/v1/auth/login/ returns 429 when the rate limit is exceeded."""
    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.login.side_effect = TooManyAttemptsError(
            "Too many login attempts. Please try again later."
        )
        mock_factory.return_value = mock_svc

        response = api_client.post(
            "/api/v1/auth/login/",
            {"email": "test@example.com", "password": "Pass1!"},
            format="json",
        )

    assert response.status_code == 429
