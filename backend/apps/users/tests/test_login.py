"""Tests — Login (tests 6–9).

6.  Successful login returns access_token, refresh_token, token_type.
7.  Invalid login (wrong password) raises AuthenticationError.
8.  Disabled account raises AccountDisabledError (but API returns same 401).
9.  Safe error responses — same 401 for wrong email and wrong password
    (no account enumeration).
"""
import pytest
from unittest.mock import patch, MagicMock

from apps.users.services.users import (
    AccountDisabledError,
    AuthenticationError,
)


# ── 6. Successful login ───────────────────────────────────────────────────────

def test_successful_login_returns_tokens(user_service, mock_user_repo, sample_user_doc):
    """Login with correct credentials returns all three token fields."""
    mock_user_repo.find_by_email.return_value = sample_user_doc

    result = user_service.login(
        email="test@example.com",
        password="ValidPass1!",
    )

    assert "access_token" in result
    assert "refresh_token" in result
    assert result["token_type"] == "Bearer"
    # Tokens should be non-empty strings
    assert result["access_token"]
    assert result["refresh_token"]


def test_successful_login_updates_last_login(user_service, mock_user_repo, sample_user_doc):
    """Login with correct credentials calls update_last_login on the repo."""
    mock_user_repo.find_by_email.return_value = sample_user_doc

    user_service.login(email="test@example.com", password="ValidPass1!")

    mock_user_repo.update_last_login.assert_called_once_with(
        sample_user_doc["user_id"]
    )


def test_successful_login_stores_refresh_token(user_service, mock_user_repo, sample_user_doc):
    """Login stores the refresh token JTI in the repository."""
    mock_user_repo.find_by_email.return_value = sample_user_doc

    user_service.login(email="test@example.com", password="ValidPass1!")

    mock_user_repo.store_refresh_token.assert_called_once()


@pytest.mark.django_db
def test_login_view_returns_200_on_success(api_client):
    """POST /api/v1/auth/login/ returns 200 with tokens on success."""
    fake_tokens = {
        "access_token": "fake.access.token",
        "refresh_token": "fake.refresh.token",
        "token_type": "Bearer",
    }

    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.login.return_value = fake_tokens
        mock_factory.return_value = mock_svc

        response = api_client.post(
            "/api/v1/auth/login/",
            {"email": "test@example.com", "password": "ValidPass1!"},
            format="json",
        )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"


# ── 7. Invalid login ──────────────────────────────────────────────────────────

def test_wrong_password_raises_authentication_error(
    user_service, mock_user_repo, sample_user_doc
):
    """Login with the wrong password raises AuthenticationError."""
    mock_user_repo.find_by_email.return_value = sample_user_doc

    with pytest.raises(AuthenticationError):
        user_service.login(
            email="test@example.com",
            password="WrongPassword1!",
        )


def test_nonexistent_email_raises_authentication_error(
    user_service, mock_user_repo
):
    """Login with an email that does not exist raises AuthenticationError."""
    mock_user_repo.find_by_email.return_value = None  # user not found

    with pytest.raises(AuthenticationError):
        user_service.login(
            email="nobody@example.com",
            password="SecurePass1!",
        )


@pytest.mark.django_db
def test_login_view_returns_401_for_wrong_credentials(api_client):
    """POST /api/v1/auth/login/ returns 401 for invalid credentials."""
    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.login.side_effect = AuthenticationError("Invalid credentials.")
        mock_factory.return_value = mock_svc

        response = api_client.post(
            "/api/v1/auth/login/",
            {"email": "test@example.com", "password": "WrongPass1!"},
            format="json",
        )

    assert response.status_code == 401


# ── 8. Disabled account ───────────────────────────────────────────────────────

def test_disabled_account_raises_account_disabled_error(
    user_service, mock_user_repo, disabled_user_doc
):
    """Login for a disabled account raises AccountDisabledError."""
    mock_user_repo.find_by_email.return_value = disabled_user_doc

    with pytest.raises(AccountDisabledError):
        user_service.login(
            email="test@example.com",
            password="ValidPass1!",
        )


@pytest.mark.django_db
def test_disabled_account_returns_401_not_403(api_client):
    """API returns 401 (not 403) for disabled accounts — does not reveal the reason."""
    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.login.side_effect = AccountDisabledError(
            "This account has been disabled."
        )
        mock_factory.return_value = mock_svc

        response = api_client.post(
            "/api/v1/auth/login/",
            {"email": "test@example.com", "password": "ValidPass1!"},
            format="json",
        )

    assert response.status_code == 401
    # Must say "Invalid credentials." — not reveal account is disabled
    assert response.json()["detail"] == "Invalid credentials."


# ── 9. Safe error responses (no account enumeration) ─────────────────────────

@pytest.mark.django_db
def test_wrong_email_and_wrong_password_return_same_response(api_client):
    """Wrong email and wrong password produce identical 401 responses.

    This prevents attackers from distinguishing whether an account exists.
    """
    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.login.side_effect = AuthenticationError("Invalid credentials.")
        mock_factory.return_value = mock_svc

        response_bad_email = api_client.post(
            "/api/v1/auth/login/",
            {"email": "nobody@example.com", "password": "SecurePass1!"},
            format="json",
        )
        response_bad_password = api_client.post(
            "/api/v1/auth/login/",
            {"email": "test@example.com", "password": "WrongPass1!"},
            format="json",
        )

    assert response_bad_email.status_code == response_bad_password.status_code == 401
    assert response_bad_email.json()["detail"] == response_bad_password.json()["detail"]


def test_login_does_not_log_password(user_service, mock_user_repo, sample_user_doc, caplog):
    """Passwords and hashes must never appear in log output during login."""
    import logging

    mock_user_repo.find_by_email.return_value = sample_user_doc

    with caplog.at_level(logging.DEBUG):
        user_service.login(email="test@example.com", password="ValidPass1!")

    log_text = caplog.text
    assert "ValidPass1!" not in log_text
    assert "argon2" not in log_text.lower() or "$argon2" not in log_text
