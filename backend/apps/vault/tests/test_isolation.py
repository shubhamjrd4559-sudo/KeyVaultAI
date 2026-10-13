"""User data isolation and IDOR/BOLA prevention tests.

Proves that User B cannot access, modify, or delete User A's credentials
through any vault endpoint — list, retrieve, create, update, soft-delete,
reveal, copy, restore, permanent-delete, recently-deleted.

Every operation is tested at the VIEW layer (HTTP) to guarantee that the
full auth + repository ownership stack prevents cross-user access.
"""
from unittest.mock import patch

import pytest
from rest_framework.test import APIClient

from apps.users.services.authentication import TokenService
from .conftest import TestAllowRateLimiter
from apps.vault.services.credential_service import CredentialService
from apps.vault.services.encryption import make_test_encryption_service
from apps.vault.repositories.credentials import CredentialNotFoundError
from apps.audit.services.audit import AuditService
from unittest.mock import MagicMock
from copy import deepcopy
from datetime import datetime, timezone


# ── Minimal in-memory repo (same as conftest but defined inline for clarity) ──

class _InMemoryRepo:
    def __init__(self):
        self.docs = {}

    def create(self, doc):
        self.docs[doc["credential_id"]] = deepcopy(doc)

    def find_all_by_user(self, user_id, filters=None, search=None):
        return [deepcopy(d) for d in self.docs.values()
                if d["user_id"] == user_id and not d.get("is_deleted")]

    def find_by_id_and_user(self, credential_id, user_id):
        d = self.docs.get(credential_id)
        if d is None or d["user_id"] != user_id or d.get("is_deleted"):
            raise CredentialNotFoundError()
        return deepcopy(d)

    def get_encrypted_password_for_owner(self, credential_id, user_id):
        return self.find_by_id_and_user(credential_id, user_id)["encrypted_password"]

    def update_by_id_and_user(self, credential_id, user_id, updates):
        self.find_by_id_and_user(credential_id, user_id)
        self.docs[credential_id].update(deepcopy(updates))
        return deepcopy(self.docs[credential_id])

    def update_last_used(self, credential_id, user_id):
        self.find_by_id_and_user(credential_id, user_id)

    def delete_by_id_and_user(self, credential_id, user_id):
        self.find_by_id_and_user(credential_id, user_id)
        del self.docs[credential_id]

    def soft_delete_by_id_and_user(self, credential_id, user_id):
        self.find_by_id_and_user(credential_id, user_id)
        self.docs[credential_id]["is_deleted"] = True
        self.docs[credential_id]["deleted_at"] = datetime.now(timezone.utc)

    def find_deleted_by_user(self, user_id):
        return [deepcopy(d) for d in self.docs.values()
                if d["user_id"] == user_id and d.get("is_deleted")]

    def restore_by_id_and_user(self, credential_id, user_id):
        d = self.docs.get(credential_id)
        if d is None or d["user_id"] != user_id or not d.get("is_deleted"):
            raise CredentialNotFoundError()
        d["is_deleted"] = False
        d["deleted_at"] = None
        return deepcopy(d)

    def permanent_delete_by_id_and_user(self, credential_id, user_id):
        d = self.docs.get(credential_id)
        if d is None or d["user_id"] != user_id or not d.get("is_deleted"):
            raise CredentialNotFoundError()
        del self.docs[credential_id]

    def find_all_encrypted_for_user(self, user_id):
        return [{"credential_id": d["credential_id"], "encrypted_password": d["encrypted_password"]}
                for d in self.docs.values() if d["user_id"] == user_id and not d.get("is_deleted")]


# ── Fixtures ──────────────────────────────────────────────────────────────────

USER_A = "user-a-uuid"
USER_B = "user-b-uuid"
EMAIL_A = "alice@example.test"
EMAIL_B = "bob@example.test"


@pytest.fixture
def repo():
    return _InMemoryRepo()


@pytest.fixture
def svc(repo):
    return CredentialService(
        repo=repo,
        encryption_service=make_test_encryption_service(),
        rate_limiter=TestAllowRateLimiter(),
        audit_service=MagicMock(spec=AuditService),
    )


@pytest.fixture
def token_service():
    return TokenService()


@pytest.fixture
def client_a(token_service):
    client = APIClient()
    token = token_service.generate_access_token(USER_A, EMAIL_A)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


@pytest.fixture
def client_b(token_service):
    client = APIClient()
    token = token_service.generate_access_token(USER_B, EMAIL_B)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


@pytest.fixture
def cred_a(svc):
    """A credential belonging to User A."""
    return svc.create_credential(USER_A, "SecretPass1!", "BankOfAmerica", username="alice")


# ── Tests — User A can access their own credential ───────────────────────────

def test_user_a_can_list_own_credentials(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.get("/api/v1/vault/credentials/")
    assert res.status_code == 200
    ids = [c["credential_id"] for c in res.data["credentials"]]
    assert cred_a["credential_id"] in ids


def test_user_a_can_retrieve_own_credential(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.get(f"/api/v1/vault/credentials/{cred_a['credential_id']}/")
    assert res.status_code == 200
    assert res.data["credential"]["credential_id"] == cred_a["credential_id"]
    assert "password" not in res.data["credential"]
    assert "encrypted_password" not in res.data["credential"]


def test_user_a_can_reveal_own_password(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/reveal/")
    assert res.status_code == 200
    assert res.data["password"] == "SecretPass1!"


def test_user_a_can_copy_own_password(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/copy/")
    assert res.status_code == 200
    assert res.data["password"] == "SecretPass1!"


def test_user_a_can_update_own_credential(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.patch(
            f"/api/v1/vault/credentials/{cred_a['credential_id']}/",
            {"website_name": "NewName"},
            format="json",
        )
    assert res.status_code == 200


def test_user_a_can_soft_delete_own_credential(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/soft-delete/")
    assert res.status_code == 200


def test_user_a_can_see_own_recently_deleted(client_a, svc, cred_a):
    svc.soft_delete_credential(cred_a["credential_id"], USER_A)
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.get("/api/v1/vault/recently-deleted/")
    assert res.status_code == 200
    ids = [c["credential_id"] for c in res.data["credentials"]]
    assert cred_a["credential_id"] in ids


def test_user_a_can_restore_own_deleted_credential(client_a, svc, cred_a):
    svc.soft_delete_credential(cred_a["credential_id"], USER_A)
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/restore/")
    assert res.status_code == 200


def test_user_a_can_permanent_delete_own_deleted_credential(client_a, svc, cred_a):
    svc.soft_delete_credential(cred_a["credential_id"], USER_A)
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.delete(f"/api/v1/vault/credentials/{cred_a['credential_id']}/permanent-delete/")
    assert res.status_code == 200


# ── Tests — User B CANNOT access User A's credential (IDOR/BOLA prevention) ──

def test_user_b_cannot_list_user_a_credentials(client_b, svc, cred_a):
    """User B's list must be empty — User A's credential must not appear."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.get("/api/v1/vault/credentials/")
    assert res.status_code == 200
    ids = [c["credential_id"] for c in res.data["credentials"]]
    assert cred_a["credential_id"] not in ids, (
        "IDOR: User B can see User A's credential in list"
    )


def test_user_b_cannot_retrieve_user_a_credential(client_b, svc, cred_a):
    """GET /credentials/<id>/ returns 404 for wrong owner — not a 200 or 403."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.get(f"/api/v1/vault/credentials/{cred_a['credential_id']}/")
    assert res.status_code == 404, (
        f"IDOR: User B got {res.status_code} instead of 404 on User A's credential detail"
    )


def test_user_b_cannot_reveal_user_a_password(client_b, svc, cred_a):
    """POST /credentials/<id>/reveal/ returns 404 for wrong owner."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/reveal/")
    assert res.status_code == 404, (
        f"IDOR: User B could reveal User A's password (got {res.status_code})"
    )


def test_user_b_cannot_copy_user_a_password(client_b, svc, cred_a):
    """POST /credentials/<id>/copy/ returns 404 for wrong owner."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/copy/")
    assert res.status_code == 404, (
        f"IDOR: User B could copy User A's password (got {res.status_code})"
    )


def test_user_b_cannot_update_user_a_credential(client_b, svc, cred_a):
    """PATCH /credentials/<id>/ returns 404 for wrong owner."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.patch(
            f"/api/v1/vault/credentials/{cred_a['credential_id']}/",
            {"website_name": "Hacked"},
            format="json",
        )
    assert res.status_code == 404, (
        f"IDOR: User B could update User A's credential (got {res.status_code})"
    )


def test_user_b_cannot_delete_user_a_credential(client_b, svc, cred_a):
    """DELETE /credentials/<id>/ returns 404 for wrong owner."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.delete(f"/api/v1/vault/credentials/{cred_a['credential_id']}/")
    assert res.status_code == 404, (
        f"IDOR: User B could permanently delete User A's credential (got {res.status_code})"
    )


def test_user_b_cannot_soft_delete_user_a_credential(client_b, svc, cred_a):
    """POST /credentials/<id>/soft-delete/ returns 404 for wrong owner."""
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/soft-delete/")
    assert res.status_code == 404, (
        f"IDOR: User B could soft-delete User A's credential (got {res.status_code})"
    )


def test_user_b_cannot_see_user_a_in_recently_deleted(client_b, svc, cred_a):
    """User B's recently-deleted list must NOT contain User A's deleted credential."""
    svc.soft_delete_credential(cred_a["credential_id"], USER_A)
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.get("/api/v1/vault/recently-deleted/")
    assert res.status_code == 200
    ids = [c["credential_id"] for c in res.data["credentials"]]
    assert cred_a["credential_id"] not in ids, (
        "IDOR: User B can see User A's recently-deleted credential"
    )


def test_user_b_cannot_restore_user_a_deleted_credential(client_b, svc, cred_a):
    """POST /credentials/<id>/restore/ returns 404 for wrong owner."""
    svc.soft_delete_credential(cred_a["credential_id"], USER_A)
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.post(f"/api/v1/vault/credentials/{cred_a['credential_id']}/restore/")
    assert res.status_code == 404, (
        f"IDOR: User B could restore User A's deleted credential (got {res.status_code})"
    )


def test_user_b_cannot_permanent_delete_user_a_credential(client_b, svc, cred_a):
    """DELETE /credentials/<id>/permanent-delete/ returns 404 for wrong owner."""
    svc.soft_delete_credential(cred_a["credential_id"], USER_A)
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_b.delete(f"/api/v1/vault/credentials/{cred_a['credential_id']}/permanent-delete/")
    assert res.status_code == 404, (
        f"IDOR: User B could permanently delete User A's credential (got {res.status_code})"
    )


# ── Response body never leaks passwords or ciphertext ────────────────────────

def test_list_response_never_contains_password_fields(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.get("/api/v1/vault/credentials/")
    assert res.status_code == 200
    for cred in res.data["credentials"]:
        assert "password" not in cred, "List response leaked 'password'"
        assert "encrypted_password" not in cred, "List response leaked 'encrypted_password'"


def test_detail_response_never_contains_password_fields(client_a, svc, cred_a):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.get(f"/api/v1/vault/credentials/{cred_a['credential_id']}/")
    assert res.status_code == 200
    cred = res.data["credential"]
    assert "password" not in cred, "Detail response leaked 'password'"
    assert "encrypted_password" not in cred, "Detail response leaked 'encrypted_password'"


def test_create_response_never_contains_password_fields(client_a, svc):
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = client_a.post(
            "/api/v1/vault/credentials/",
            {"website_name": "GitHub", "username": "alice", "password": "StrongPass1!"},
            format="json",
        )
    assert res.status_code == 201
    cred = res.data["credential"]
    assert "password" not in cred, "Create response leaked 'password'"
    assert "encrypted_password" not in cred, "Create response leaked 'encrypted_password'"


# ── Unauthenticated access to all endpoints returns 401 ──────────────────────

@pytest.mark.parametrize("method,path", [
    ("GET",    "/api/v1/vault/credentials/"),
    ("POST",   "/api/v1/vault/credentials/"),
    ("GET",    "/api/v1/vault/credentials/some-id/"),
    ("PATCH",  "/api/v1/vault/credentials/some-id/"),
    ("DELETE", "/api/v1/vault/credentials/some-id/"),
    ("POST",   "/api/v1/vault/credentials/some-id/reveal/"),
    ("POST",   "/api/v1/vault/credentials/some-id/copy/"),
    ("POST",   "/api/v1/vault/credentials/some-id/soft-delete/"),
    ("GET",    "/api/v1/vault/recently-deleted/"),
    ("POST",   "/api/v1/vault/credentials/some-id/restore/"),
    ("DELETE", "/api/v1/vault/credentials/some-id/permanent-delete/"),
])
def test_all_vault_endpoints_require_authentication(method, path, svc):
    client = APIClient()  # no credentials
    with patch("apps.vault.views._get_credential_service", return_value=svc):
        res = getattr(client, method.lower())(path, format="json")
    assert res.status_code == 401, (
        f"Endpoint {method} {path} returned {res.status_code} for unauthenticated request "
        f"— expected 401"
    )
