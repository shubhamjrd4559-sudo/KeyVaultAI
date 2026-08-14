import base64

import pytest
from django.test import override_settings

from apps.vault.services.encryption import EncryptionError, EncryptionService, _build_service, make_test_encryption_service


def test_encryption_decryption_round_trip():
    service = make_test_encryption_service()
    encrypted = service.encrypt("Sup3rSecret!")
    assert encrypted != "Sup3rSecret!"
    assert service.decrypt(encrypted) == "Sup3rSecret!"


def test_encryption_uses_a_fresh_nonce_each_time():
    service = make_test_encryption_service()
    assert service.encrypt("same-password") != service.encrypt("same-password")


def test_tampered_ciphertext_is_rejected():
    service = make_test_encryption_service()
    payload = bytearray(base64.urlsafe_b64decode(service.encrypt("Sup3rSecret!").encode("ascii")))
    payload[-1] ^= 1
    with pytest.raises(EncryptionError):
        service.decrypt(base64.urlsafe_b64encode(payload).decode("ascii"))


@override_settings(ENCRYPTION_KEY="")
def test_missing_key_fails_closed():
    with pytest.raises(EncryptionError):
        _build_service()


@override_settings(ENCRYPTION_KEY="aW52YWxpZA==")
def test_invalid_key_length_fails_closed():
    with pytest.raises(EncryptionError):
        _build_service()


def test_encryption_requires_32_byte_key():
    with pytest.raises(ValueError):
        EncryptionService(b"too-short")
