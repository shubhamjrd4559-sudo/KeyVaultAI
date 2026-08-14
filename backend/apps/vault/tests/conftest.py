from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from rest_framework.test import APIClient

from apps.audit.services.audit import AuditService
from apps.users.services.authentication import TokenService
from apps.users.services.rate_limiting import NullRateLimiter
from apps.vault.repositories.credentials import CredentialNotFoundError
from apps.vault.services.credential_service import CredentialService
from apps.vault.services.encryption import make_test_encryption_service


class InMemoryCredentialRepository:
    """Owner-scoped repository double that avoids a MongoDB dependency."""

    def __init__(self):
        self.documents = {}

    def create(self, doc):
        self.documents[doc["credential_id"]] = deepcopy(doc)

    def find_all_by_user(self, user_id, filters=None, search=None):
        docs = [deepcopy(doc) for doc in self.documents.values() if doc["user_id"] == user_id]
        if filters:
            docs = [doc for doc in docs if all(doc.get(key) == value for key, value in filters.items())]
        if search:
            needle = search.lower()
            docs = [doc for doc in docs if needle in " ".join(str(doc.get(key, "")) for key in ("website_name", "website_url", "username")).lower()]
        return docs

    def find_by_id_and_user(self, credential_id, user_id):
        doc = self.documents.get(credential_id)
        if doc is None or doc["user_id"] != user_id:
            raise CredentialNotFoundError()
        return deepcopy(doc)

    def get_encrypted_password_for_owner(self, credential_id, user_id):
        return self.find_by_id_and_user(credential_id, user_id)["encrypted_password"]

    def update_by_id_and_user(self, credential_id, user_id, updates):
        self.find_by_id_and_user(credential_id, user_id)
        self.documents[credential_id].update(deepcopy(updates))
        return deepcopy(self.documents[credential_id])

    def update_last_used(self, credential_id, user_id):
        self.find_by_id_and_user(credential_id, user_id)
        self.documents[credential_id]["last_used_at"] = datetime.now(timezone.utc)

    def delete_by_id_and_user(self, credential_id, user_id):
        self.find_by_id_and_user(credential_id, user_id)
        del self.documents[credential_id]


@pytest.fixture
def repo():
    return InMemoryCredentialRepository()


@pytest.fixture
def audit():
    return MagicMock(spec=AuditService)


@pytest.fixture
def vault_service(repo, audit):
    return CredentialService(repo, make_test_encryption_service(), NullRateLimiter(), audit)


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def token_service():
    return TokenService()


@pytest.fixture
def authenticated_client(api_client, token_service):
    token = token_service.generate_access_token("owner-1", "owner@example.test")
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return api_client
