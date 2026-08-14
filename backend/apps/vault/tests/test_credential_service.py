import pytest

from apps.audit.services.audit import AuditEvent
from apps.users.services.rate_limiting import RateLimiter
from apps.vault.repositories.credentials import CredentialNotFoundError
from apps.vault.services.credential_service import CredentialService, TooManyAttemptsError
from apps.vault.services.encryption import make_test_encryption_service


def create(service, user_id="owner-1", password="Sup3rSecret!"):
    return service.create_credential(user_id, password, "Example", username="owner", category="work")


def test_create_encrypts_and_never_persists_plaintext(vault_service, repo):
    credential = create(vault_service)
    stored = repo.documents[credential["credential_id"]]
    assert stored["encrypted_password"] != "Sup3rSecret!"
    assert "Sup3rSecret!" not in str(stored)
    assert "encrypted_password" not in credential
    assert "password" not in credential


def test_list_returns_only_current_users_credentials(vault_service):
    create(vault_service, "owner-1")
    create(vault_service, "owner-2")
    credentials = vault_service.list_credentials("owner-1")
    assert len(credentials) == 1
    assert "encrypted_password" not in credentials[0]
    assert "notes" not in credentials[0]


def test_cross_user_detail_access_is_denied(vault_service):
    credential = create(vault_service)
    with pytest.raises(CredentialNotFoundError):
        vault_service.get_credential(credential["credential_id"], "owner-2")


def test_detail_never_exposes_password(vault_service):
    credential = create(vault_service)
    detail = vault_service.get_credential(credential["credential_id"], "owner-1")
    assert "password" not in detail
    assert "encrypted_password" not in detail


def test_update_changes_safe_metadata(vault_service):
    credential = create(vault_service)
    updated = vault_service.update_credential(credential["credential_id"], "owner-1", {"website_name": "Changed"})
    assert updated["website_name"] == "Changed"


def test_password_update_reencrypts(vault_service, repo):
    credential = create(vault_service)
    before = repo.documents[credential["credential_id"]]["encrypted_password"]
    vault_service.update_credential(credential["credential_id"], "owner-1", {"password": "NewSecret2@"})
    after = repo.documents[credential["credential_id"]]["encrypted_password"]
    assert after != before
    assert vault_service.reveal_password(credential["credential_id"], "owner-1") == "NewSecret2@"


def test_delete_and_wrong_user_delete_denied(vault_service):
    credential = create(vault_service)
    with pytest.raises(CredentialNotFoundError):
        vault_service.delete_credential(credential["credential_id"], "owner-2")
    vault_service.delete_credential(credential["credential_id"], "owner-1")
    with pytest.raises(CredentialNotFoundError):
        vault_service.get_credential(credential["credential_id"], "owner-1")


def test_reveal_and_copy_require_owner(vault_service):
    credential = create(vault_service)
    assert vault_service.reveal_password(credential["credential_id"], "owner-1") == "Sup3rSecret!"
    assert vault_service.copy_password(credential["credential_id"], "owner-1") == "Sup3rSecret!"
    with pytest.raises(CredentialNotFoundError):
        vault_service.reveal_password(credential["credential_id"], "owner-2")
    with pytest.raises(CredentialNotFoundError):
        vault_service.copy_password(credential["credential_id"], "owner-2")


def test_audit_events_are_emitted(vault_service, audit):
    credential = create(vault_service)
    vault_service.get_credential(credential["credential_id"], "owner-1")
    vault_service.reveal_password(credential["credential_id"], "owner-1")
    events = [call.args[0] for call in audit.log.call_args_list]
    assert AuditEvent.CREDENTIAL_CREATED in events
    assert AuditEvent.CREDENTIAL_VIEWED in events
    assert AuditEvent.PASSWORD_REVEALED in events


class BlockingLimiter(RateLimiter):
    def is_allowed(self, action, key):
        return False

    def record(self, action, key):
        raise AssertionError("blocked requests must not be recorded")


def test_reveal_and_copy_rate_limit_hooks(repo, audit):
    service = CredentialService(repo, make_test_encryption_service(), BlockingLimiter(), audit)
    credential = create(service)
    with pytest.raises(TooManyAttemptsError):
        service.reveal_password(credential["credential_id"], "owner-1")
    with pytest.raises(TooManyAttemptsError):
        service.copy_password(credential["credential_id"], "owner-1")
