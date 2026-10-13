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


def test_soft_delete_and_recovery_flow(authenticated_client, vault_service):
    # 1. Create a credential
    cred = vault_service.create_credential("owner-1", "Secret1!", "TikTok", username="tiktok_user")
    cred_id = cred["credential_id"]

    with patch("apps.vault.views._get_credential_service", return_value=vault_service):
        # 2. Verify it shows in active vault
        active_list = authenticated_client.get("/api/v1/vault/credentials/")
        assert active_list.status_code == 200
        assert any(c["credential_id"] == cred_id for c in active_list.data["credentials"])

        # 3. Soft-delete the credential
        delete_res = authenticated_client.post(f"/api/v1/vault/credentials/{cred_id}/soft-delete/")
        assert delete_res.status_code == 200
        assert delete_res.data["detail"] == "Credential moved to Recently Deleted."

        # 4. Verify removed from active vault
        active_list_after = authenticated_client.get("/api/v1/vault/credentials/")
        assert not any(c["credential_id"] == cred_id for c in active_list_after.data["credentials"])

        # 5. Verify listed in recently deleted
        deleted_list = authenticated_client.get("/api/v1/vault/recently-deleted/")
        assert deleted_list.status_code == 200
        assert any(c["credential_id"] == cred_id for c in deleted_list.data["credentials"])
        # Verify no passwords or ciphertexts leaked
        for c in deleted_list.data["credentials"]:
            assert "password" not in c
            assert "encrypted_password" not in c
            assert "deleted_at" in c

        # 6. Restore the credential
        restore_res = authenticated_client.post(f"/api/v1/vault/credentials/{cred_id}/restore/")
        assert restore_res.status_code == 200
        assert restore_res.data["credential"]["credential_id"] == cred_id

        # 7. Verify back in active vault
        active_list_restored = authenticated_client.get("/api/v1/vault/credentials/")
        assert any(c["credential_id"] == cred_id for c in active_list_restored.data["credentials"])

        # 8. Soft-delete again and permanently delete
        authenticated_client.post(f"/api/v1/vault/credentials/{cred_id}/soft-delete/")
        perm_res = authenticated_client.delete(f"/api/v1/vault/credentials/{cred_id}/permanent-delete/")
        assert perm_res.status_code == 200

        # 9. Verify gone completely
        deleted_list_final = authenticated_client.get("/api/v1/vault/recently-deleted/")
        assert not any(c["credential_id"] == cred_id for c in deleted_list_final.data["credentials"])


def test_soft_delete_owner_isolation(api_client, token_service, vault_service):
    # Credential belongs to owner-1
    cred = vault_service.create_credential("owner-1", "Secret1!", "TikTok", username="owner1")
    cred_id = cred["credential_id"]

    # User 2 tries to access/delete/restore owner-1's credential
    token_user2 = token_service.generate_access_token("owner-2", "user2@example.test")
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_user2}")

    with patch("apps.vault.views._get_credential_service", return_value=vault_service):
        # User 2 cannot soft delete
        res = api_client.post(f"/api/v1/vault/credentials/{cred_id}/soft-delete/")
        assert res.status_code == 404

        # Owner 1 soft-deletes it
        vault_service.soft_delete_credential(cred_id, "owner-1")

        # User 2 cannot see it in recently deleted
        res_del = api_client.get("/api/v1/vault/recently-deleted/")
        assert res_del.status_code == 200
        assert not any(c["credential_id"] == cred_id for c in res_del.data["credentials"])

        # User 2 cannot restore it
        res_rest = api_client.post(f"/api/v1/vault/credentials/{cred_id}/restore/")
        assert res_rest.status_code == 404

        # User 2 cannot permanently delete it
        res_perm = api_client.delete(f"/api/v1/vault/credentials/{cred_id}/permanent-delete/")
        assert res_perm.status_code == 404
