from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from apps.users.services.email_tokens import hash_email_token
from apps.users.services.users import EmailNotVerifiedError, InvalidEmailTokenError


def test_registration_creates_pending_user_and_sends_verification(user_service, mock_user_repo):
    mock_user_repo.find_by_email.return_value = None
    user_service.register("new@example.com", "SecurePass1!", "New User")

    stored_user = mock_user_repo.create_user.call_args.args[0]
    assert stored_user["email_verified"] is False
    assert stored_user["account_status"] == "pending_verification"
    mock_user_repo.store_email_verification_token.assert_called_once()
    user_service._send_verification_email.assert_called_once()
    raw_token = user_service._send_verification_email.call_args.args[2]
    assert raw_token not in str(mock_user_repo.store_email_verification_token.call_args)


def test_unverified_user_cannot_login(user_service, mock_user_repo, sample_user_doc):
    mock_user_repo.find_by_email.return_value = {**sample_user_doc, "email_verified": False}
    with pytest.raises(EmailNotVerifiedError):
        user_service.login("test@example.com", "ValidPass1!")


def test_verification_consumes_hashed_single_use_token(user_service, mock_user_repo, mock_audit):
    raw = "random-verification-token-value"
    mock_user_repo.consume_email_verification_token.return_value = {"user_id": "user-123"}
    mock_user_repo.mark_email_verified.return_value = True

    user_service.verify_email(raw)

    mock_user_repo.consume_email_verification_token.assert_called_once()
    assert mock_user_repo.consume_email_verification_token.call_args.args[0] == hash_email_token(raw)
    mock_user_repo.mark_email_verified.assert_called_once_with("user-123")


def test_expired_or_unknown_verification_token_is_rejected(user_service, mock_user_repo):
    mock_user_repo.consume_email_verification_token.return_value = None
    with pytest.raises(InvalidEmailTokenError):
        user_service.verify_email("random-verification-token-value")


def test_password_reset_request_is_ambiguous_for_unknown_email(user_service, mock_user_repo):
    mock_user_repo.find_by_email.return_value = None
    user_service.request_password_reset("unknown@example.com")
    user_service._send_password_reset_email.assert_not_called()


def test_password_reset_uses_hashed_single_use_token_and_revokes_sessions(
    user_service, mock_user_repo, mock_audit
):
    raw = "random-password-reset-token-value"
    mock_user_repo.consume_password_reset_token.return_value = {"user_id": "user-123"}
    mock_user_repo.update_password_hash.return_value = True

    user_service.reset_password(raw, "ChangedPass2!")

    assert mock_user_repo.consume_password_reset_token.call_args.args[0] == hash_email_token(raw)
    mock_user_repo.update_password_hash.assert_called_once()
    mock_user_repo.revoke_all_user_tokens.assert_called_once_with("user-123")
    mock_audit.log.assert_called()


def test_legacy_account_without_email_verified_field_blocked_and_can_reverify(
    user_service, mock_user_repo, sample_user_doc
):
    """Legacy accounts created before email verification existed have no email_verified key.
    
    They must be safely blocked at login, allowed to request verification via resend,
    and preserved without altering password hash.
    """
    # Simulate a legacy document lacking email_verified and account_status keys
    legacy_doc = {
        k: v for k, v in sample_user_doc.items()
        if k not in ("email_verified", "account_status")
    }
    mock_user_repo.find_by_email.return_value = legacy_doc

    # 1. Login must fail closed with EmailNotVerifiedError
    with pytest.raises(EmailNotVerifiedError):
        user_service.login("test@example.com", "ValidPass1!")

    # 2. Resend verification must issue token to legacy account's email
    user_service.resend_verification("test@example.com")
    mock_user_repo.store_email_verification_token.assert_called_once()
    user_service._send_verification_email.assert_called_once()
    assert user_service._send_verification_email.call_args.args[0] == "test@example.com"
