"""Tests — JWT tokens (tests 10–13).

10. Access token encodes the correct user_id and email.
11. Refresh token validates and returns user_id (sub).
12. Expired access token raises jwt.ExpiredSignatureError.
13. Unauthorized request to a protected endpoint returns 401.
"""
import uuid
from datetime import timedelta
from unittest.mock import patch, MagicMock

import jwt
import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from apps.users.authentication import AuthenticatedUser, JWTAuthentication
from apps.users.services.authentication import TokenService


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_token_service() -> TokenService:
    return TokenService()


# ── 10. Access token validation ───────────────────────────────────────────────

def test_access_token_contains_user_id_and_email(token_service):
    """Generated access token decodes to the correct sub and email claims."""
    user_id = str(uuid.uuid4())
    email = "access@example.com"

    token = token_service.generate_access_token(user_id, email)
    payload = token_service.decode_access_token(token)

    assert payload["sub"] == user_id
    assert payload["email"] == email
    assert payload["type"] == "access"


def test_access_token_decode_rejects_refresh_token(token_service):
    """decode_access_token raises InvalidTokenError when given a refresh token."""
    user_id = str(uuid.uuid4())
    refresh_token, _, _ = token_service.generate_refresh_token(user_id)

    with pytest.raises(jwt.InvalidTokenError):
        token_service.decode_access_token(refresh_token)


def test_access_token_decode_rejects_bad_signature(token_service):
    """A token signed with a different secret is rejected."""
    user_id = str(uuid.uuid4())
    token = token_service.generate_access_token(user_id, "x@x.com")

    # Tamper with signature
    parts = token.split(".")
    tampered = parts[0] + "." + parts[1] + ".invalidsignature"

    with pytest.raises(jwt.PyJWTError):
        token_service.decode_access_token(tampered)


# ── 11. Refresh token validation ──────────────────────────────────────────────

def test_refresh_token_encodes_user_id(token_service):
    """Generated refresh token decodes to the correct sub and jti."""
    user_id = str(uuid.uuid4())

    token, jti, expires_at = token_service.generate_refresh_token(user_id)
    payload = token_service.decode_refresh_token(token)

    assert payload["sub"] == user_id
    assert payload["jti"] == jti
    assert payload["type"] == "refresh"


def test_refresh_token_decode_rejects_access_token(token_service):
    """decode_refresh_token raises InvalidTokenError when given an access token."""
    user_id = str(uuid.uuid4())
    access_token = token_service.generate_access_token(user_id, "x@x.com")

    with pytest.raises(jwt.InvalidTokenError):
        token_service.decode_refresh_token(access_token)


def test_refresh_token_rotation_issues_new_pair(
    user_service, mock_user_repo, token_service, sample_user_doc
):
    """Token refresh returns a new access + refresh pair and revokes the old JTI."""
    user_id = sample_user_doc["user_id"]
    old_refresh, old_jti, old_exp = token_service.generate_refresh_token(user_id)

    mock_user_repo.is_refresh_token_valid.return_value = True
    mock_user_repo.find_by_user_id.return_value = sample_user_doc

    result = user_service.refresh_tokens(refresh_token=old_refresh)

    # Old token revoked
    mock_user_repo.revoke_refresh_token.assert_called_with(old_jti)
    # New tokens returned
    assert "access_token" in result
    assert "refresh_token" in result
    # New refresh token must differ from old
    assert result["refresh_token"] != old_refresh


# ── 12. Expired token ─────────────────────────────────────────────────────────

@override_settings(JWT_ACCESS_TOKEN_LIFETIME=timedelta(seconds=-1))
def test_expired_access_token_raises_error():
    """An access token with a past expiry raises ExpiredSignatureError on decode."""
    ts = TokenService()
    user_id = str(uuid.uuid4())
    token = ts.generate_access_token(user_id, "expired@example.com")

    with pytest.raises(jwt.ExpiredSignatureError):
        ts.decode_access_token(token)


@override_settings(JWT_REFRESH_TOKEN_LIFETIME=timedelta(seconds=-1))
def test_expired_refresh_token_raises_authentication_error(
    user_service, token_service
):
    """service.refresh_tokens raises AuthenticationError for an expired refresh token."""
    from apps.users.services.users import AuthenticationError

    # Generate with negative lifetime so it's immediately expired
    ts_expired = TokenService()
    user_id = str(uuid.uuid4())
    old_refresh, _, _ = ts_expired.generate_refresh_token(user_id)

    with pytest.raises(AuthenticationError, match="expired"):
        user_service.refresh_tokens(refresh_token=old_refresh)


# ── 13. Unauthorized protected request ───────────────────────────────────────

@pytest.mark.django_db
def test_protected_endpoint_without_token_returns_401(api_client):
    """POST /api/v1/auth/logout/ without a token returns 401."""
    response = api_client.post(
        "/api/v1/auth/logout/",
        {"refresh_token": "any"},
        format="json",
    )
    assert response.status_code == 401


@pytest.mark.django_db
def test_protected_endpoint_with_invalid_token_returns_401(api_client):
    """POST /api/v1/auth/logout/ with a bad token returns 401."""
    api_client.credentials(HTTP_AUTHORIZATION="Bearer totally.invalid.token")
    response = api_client.post(
        "/api/v1/auth/logout/",
        {"refresh_token": "any"},
        format="json",
    )
    assert response.status_code == 401


@pytest.mark.django_db
def test_protected_endpoint_with_valid_token_succeeds(api_client, token_service):
    """POST /api/v1/auth/logout/ with a valid access token returns 200."""
    user_id = str(uuid.uuid4())
    access_token = token_service.generate_access_token(user_id, "auth@example.com")

    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.logout.return_value = None
        mock_factory.return_value = mock_svc

        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        response = api_client.post(
            "/api/v1/auth/logout/",
            {"refresh_token": "some.refresh.token"},
            format="json",
        )

    assert response.status_code == 200


@pytest.mark.django_db
def test_jwt_authentication_sets_request_user(api_client, token_service):
    """A valid Bearer token results in request.user being an AuthenticatedUser."""
    user_id = str(uuid.uuid4())
    email = "verify@example.com"
    access_token = token_service.generate_access_token(user_id, email)

    captured_user = {}

    with patch("apps.users.views._get_user_service") as mock_factory:
        def capture_logout(refresh_token, user_id, ip_address=None):
            captured_user["user_id"] = user_id

        mock_svc = MagicMock()
        mock_svc.logout.side_effect = capture_logout
        mock_factory.return_value = mock_svc

        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        api_client.post(
            "/api/v1/auth/logout/",
            {"refresh_token": "dummy"},
            format="json",
        )

    assert captured_user["user_id"] == user_id
