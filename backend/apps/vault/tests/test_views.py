from unittest.mock import patch

from django.urls import resolve


def test_vault_url_resolution():
    assert resolve("/api/v1/vault/credentials/").url_name == "credential-list-create"
    assert resolve("/api/v1/vault/credentials/cred-1/reveal/").url_name == "credential-reveal"
    assert resolve("/api/v1/vault/credentials/cred-1/copy/").url_name == "credential-copy"


def test_unauthenticated_creation_is_denied(api_client):
    response = api_client.post("/api/v1/vault/credentials/", {"website_name": "Example", "username": "u", "password": "Secret1!"}, format="json")
    assert response.status_code == 401


def test_authenticated_creation_uses_jwt_user_and_safe_response(authenticated_client, vault_service):
    with patch("apps.vault.views._get_credential_service", return_value=vault_service):
        response = authenticated_client.post("/api/v1/vault/credentials/", {"website_name": "Example", "username": "u", "password": "Secret1!"}, format="json")
    assert response.status_code == 201
    assert "password" not in response.data["credential"]
    assert "encrypted_password" not in response.data["credential"]


def test_list_and_detail_use_authenticated_service(authenticated_client, vault_service):
    credential = vault_service.create_credential("owner-1", "Secret1!", "Example", username="u")
    with patch("apps.vault.views._get_credential_service", return_value=vault_service):
        listed = authenticated_client.get("/api/v1/vault/credentials/")
        detail = authenticated_client.get(f"/api/v1/vault/credentials/{credential['credential_id']}/")
    assert listed.status_code == 200
    assert listed.data["count"] == 1
    assert detail.status_code == 200
    assert "password" not in detail.data["credential"]
