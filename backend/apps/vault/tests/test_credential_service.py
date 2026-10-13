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


def test_soft_delete_restore_and_audit(vault_service, audit):
    credential = create(vault_service)
    cid = credential["credential_id"]

    # Soft delete
    vault_service.soft_delete_credential(cid, "owner-1")
    assert not any(c["credential_id"] == cid for c in vault_service.list_credentials("owner-1"))
    deleted = vault_service.list_deleted_credentials("owner-1")
    assert any(c["credential_id"] == cid for c in deleted)

    # Restore
    restored = vault_service.restore_credential(cid, "owner-1")
    assert restored["credential_id"] == cid
    assert any(c["credential_id"] == cid for c in vault_service.list_credentials("owner-1"))
    assert not any(c["credential_id"] == cid for c in vault_service.list_deleted_credentials("owner-1"))

    # Audit events
    events = [call.args[0] for call in audit.log.call_args_list]
    assert AuditEvent.CREDENTIAL_SOFT_DELETED in events
    assert AuditEvent.CREDENTIAL_RESTORED in events


def test_72_hour_permanent_cleanup(repo, vault_service):
    from datetime import timedelta, timezone, datetime

    # 1. Active credential (should NOT be deleted)
    active = vault_service.create_credential("owner-1", "Secret1!", "ActiveApp", username="active")

    # 2. Recently deleted credential (2 hours ago, should NOT be deleted)
    recent = vault_service.create_credential("owner-1", "Secret1!", "RecentApp", username="recent")
    vault_service.soft_delete_credential(recent["credential_id"], "owner-1")
    repo.documents[recent["credential_id"]]["deleted_at"] = datetime.now(timezone.utc) - timedelta(hours=2)

    # 3. Still-recoverable credential (71 hours ago, must NOT be deleted)
    expired = vault_service.create_credential("owner-1", "Secret1!", "ExpiredApp", username="expired")
    vault_service.soft_delete_credential(expired["credential_id"], "owner-1")
    repo.documents[expired["credential_id"]]["deleted_at"] = datetime.now(timezone.utc) - timedelta(hours=71)

    # 4. Expired deleted credential (73 hours ago, SHOULD be deleted)
    purge = vault_service.create_credential("owner-1", "Secret1!", "PurgeApp", username="purge")
    vault_service.soft_delete_credential(purge["credential_id"], "owner-1")
    repo.documents[purge["credential_id"]]["deleted_at"] = datetime.now(timezone.utc) - timedelta(hours=73)

    # 5. Restored credential, should NOT be deleted
    restored = vault_service.create_credential("owner-1", "Secret1!", "RestoredApp", username="restored")
    vault_service.soft_delete_credential(restored["credential_id"], "owner-1")
    vault_service.restore_credential(restored["credential_id"], "owner-1")

    # Run cleanup
    count = repo.permanent_delete_expired()
    assert count == 1

    # Verify results
    assert active["credential_id"] in repo.documents
    assert recent["credential_id"] in repo.documents
    assert restored["credential_id"] in repo.documents
    assert expired["credential_id"] in repo.documents
    assert purge["credential_id"] not in repo.documents

    # Idempotent: running again deletes 0
    count_second = repo.permanent_delete_expired()
    assert count_second == 0


def test_restore_is_rejected_after_72_hour_recovery_window(repo, vault_service):
    from datetime import timedelta, timezone, datetime

    expired = create(vault_service)
    vault_service.soft_delete_credential(expired["credential_id"], "owner-1")
    repo.documents[expired["credential_id"]]["deleted_at"] = datetime.now(timezone.utc) - timedelta(hours=73)
    with pytest.raises(CredentialNotFoundError):
        vault_service.restore_credential(expired["credential_id"], "owner-1")


def test_celery_task_permanent_delete_expired():
    from unittest.mock import patch, MagicMock
    from apps.vault.tasks import permanent_delete_expired_credentials

    # Test when db is None
    with patch("apps.common.database.get_db", return_value=None):
        result = permanent_delete_expired_credentials()
        assert result == 0

    # Test with mock db and repo
    mock_db = MagicMock()
    with patch("apps.common.database.get_db", return_value=mock_db):
        with patch("apps.vault.repositories.credentials.CredentialRepository.permanent_delete_expired", return_value=3):
            result = permanent_delete_expired_credentials()
            assert result == 3

