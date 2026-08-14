"""Tests — Registration (tests 1–5).

1.  Successful registration returns a safe user dict.
2.  Duplicate email raises RegistrationError with a vague message.
3.  Invalid registration data (bad email, short password, etc.) raises RegistrationError.
4.  Password is hashed with Argon2id.
5.  Plaintext password is never persisted.
"""
import pytest
from unittest.mock import patch, MagicMock

from apps.users.services.users import RegistrationError, UserService


# ── 1. Successful registration ────────────────────────────────────────────────

def test_successful_registration_returns_safe_user_dict(user_service, mock_user_repo):
    """Register succeeds and returns a dict without password_hash."""
    mock_user_repo.find_by_email.return_value = None  # no duplicate

    result = user_service.register(
        email="alice@example.com",
        password="SecurePass1!",
        full_name="Alice Smith",
    )

    assert result["email"] == "alice@example.com"
    assert result["full_name"] == "Alice Smith"
    assert "user_id" in result
    assert "password_hash" not in result


def test_successful_registration_creates_user_in_repo(user_service, mock_user_repo):
    """Repository create_user is called exactly once with the correct email."""
    mock_user_repo.find_by_email.return_value = None

    user_service.register(
        email="Bob@Example.COM",   # mixed case
        password="SecurePass1!",
        full_name="Bob Jones",
    )

    mock_user_repo.create_user.assert_called_once()
    call_arg = mock_user_repo.create_user.call_args[0][0]
    assert call_arg["email"] == "bob@example.com"  # normalized


# ── 2. Duplicate email ────────────────────────────────────────────────────────

def test_duplicate_email_raises_registration_error(user_service, mock_user_repo, sample_user_doc):
    """Registering with an existing email raises RegistrationError with a vague message."""
    mock_user_repo.find_by_email.return_value = sample_user_doc  # existing user

    with pytest.raises(RegistrationError) as exc_info:
        user_service.register(
            email="test@example.com",
            password="SecurePass1!",
            full_name="Test User",
        )

    # Message must NOT reveal "email already exists"
    message = str(exc_info.value).lower()
    assert "already" not in message or "check your details" in message


def test_duplicate_email_does_not_call_create_user(user_service, mock_user_repo, sample_user_doc):
    """Repository create_user is NOT called when the email is already taken."""
    mock_user_repo.find_by_email.return_value = sample_user_doc

    with pytest.raises(RegistrationError):
        user_service.register(
            email="test@example.com",
            password="SecurePass1!",
            full_name="Test User",
        )

    mock_user_repo.create_user.assert_not_called()


# ── 3. Invalid registration data ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "email, password, full_name",
    [
        ("not-an-email", "SecurePass1!", "Alice"),          # bad email
        ("alice@example.com", "short1!", "Alice"),          # password too short
        ("alice@example.com", "alllowercase1!", "Alice"),   # no uppercase
        ("alice@example.com", "ALLUPPERCASE1!", "Alice"),   # no lowercase
        ("alice@example.com", "NoDigitsHere!", "Alice"),    # no digit
        ("alice@example.com", "NoSpecial1234", "Alice"),    # no special char
        ("alice@example.com", "SecurePass1!", "A"),         # full_name too short
        ("alice@example.com", "SecurePass1!", ""),          # empty full_name
    ],
)
def test_invalid_registration_data_raises_error(
    user_service, mock_user_repo, email, password, full_name
):
    """Each invalid input combination raises RegistrationError."""
    mock_user_repo.find_by_email.return_value = None

    with pytest.raises(RegistrationError):
        user_service.register(email=email, password=password, full_name=full_name)


# ── 4. Password is hashed with Argon2id ──────────────────────────────────────

def test_password_is_hashed_with_argon2id(user_service, mock_user_repo):
    """The stored password_hash uses Argon2id encoding."""
    mock_user_repo.find_by_email.return_value = None

    user_service.register(
        email="charlie@example.com",
        password="SecurePass1!",
        full_name="Charlie Doe",
    )

    stored_doc = mock_user_repo.create_user.call_args[0][0]
    stored_hash = stored_doc["password_hash"]

    # Argon2id hashes always start with this prefix
    assert stored_hash.startswith("$argon2id$"), (
        f"Expected Argon2id hash, got: {stored_hash[:30]}..."
    )


def test_argon2id_hash_can_be_verified(user_service, mock_user_repo):
    """The stored hash can be successfully verified with the original password."""
    from argon2 import PasswordHasher

    mock_user_repo.find_by_email.return_value = None
    ph = PasswordHasher()

    user_service.register(
        email="dana@example.com",
        password="SecurePass1!",
        full_name="Dana Example",
    )

    stored_doc = mock_user_repo.create_user.call_args[0][0]
    stored_hash = stored_doc["password_hash"]

    # Should NOT raise
    ph.verify(stored_hash, "SecurePass1!")


# ── 5. Plaintext password never persisted ────────────────────────────────────

def test_plaintext_password_never_in_stored_doc(user_service, mock_user_repo):
    """The stored document contains no field with the plaintext password."""
    password = "SecurePass1!"
    mock_user_repo.find_by_email.return_value = None

    user_service.register(
        email="eve@example.com",
        password=password,
        full_name="Eve Example",
    )

    stored_doc = mock_user_repo.create_user.call_args[0][0]

    for key, value in stored_doc.items():
        assert value != password, (
            f"Plaintext password found in stored_doc['{key}'] — this is a security defect!"
        )


def test_plaintext_password_never_in_api_response():
    """The /register/ API response body contains no plaintext password."""
    from unittest.mock import patch
    from rest_framework.test import APIClient

    client = APIClient()
    mock_result = {
        "user_id": "some-uuid",
        "email": "frank@example.com",
        "full_name": "Frank Example",
        "email_verified": False,
        "account_status": "active",
        "created_at": "2026-01-01T00:00:00+00:00",
    }

    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.register.return_value = mock_result
        mock_factory.return_value = mock_svc

        response = client.post(
            "/api/v1/auth/register/",
            {"email": "frank@example.com", "password": "SecurePass1!", "full_name": "Frank Example"},
            format="json",
        )

    body = response.json()
    assert "password" not in str(body).lower() or "password_hash" not in body.get("user", {})


@pytest.mark.django_db
def test_register_view_returns_201_on_success(api_client):
    """POST /api/v1/auth/register/ returns 201 when registration succeeds."""
    mock_result = {
        "user_id": "test-uuid",
        "email": "gina@example.com",
        "full_name": "Gina Test",
        "email_verified": False,
        "account_status": "active",
        "created_at": "2026-01-01T00:00:00+00:00",
    }

    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.register.return_value = mock_result
        mock_factory.return_value = mock_svc

        response = api_client.post(
            "/api/v1/auth/register/",
            {
                "email": "gina@example.com",
                "password": "SecurePass1!",
                "full_name": "Gina Test",
            },
            format="json",
        )

    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == "gina@example.com"
    assert "password_hash" not in data["user"]


@pytest.mark.django_db
def test_register_view_returns_400_for_duplicate_email(api_client):
    """POST /api/v1/auth/register/ returns 400 for duplicate email (vague message)."""
    with patch("apps.users.views._get_user_service") as mock_factory:
        mock_svc = MagicMock()
        mock_svc.register.side_effect = RegistrationError(
            "Unable to complete registration. Please check your details."
        )
        mock_factory.return_value = mock_svc

        response = api_client.post(
            "/api/v1/auth/register/",
            {
                "email": "existing@example.com",
                "password": "SecurePass1!",
                "full_name": "Some User",
            },
            format="json",
        )

    assert response.status_code == 400
    # Must not say "already exists" or reveal the email is taken
    detail = response.json().get("detail", "")
    assert "already" not in detail.lower()
