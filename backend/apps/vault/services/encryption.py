"""AES-256-GCM encryption service for credential passwords.

Design:
- Each encryption call generates a cryptographically random 12-byte nonce.
- GCM produces a 16-byte authentication tag that prevents silent tampering.
- Ciphertext format: base64url(nonce ‖ ciphertext ‖ tag)
  where ‖ denotes concatenation.
- Decryption raises cryptography.exceptions.InvalidTag if the data was tampered.
- The key is supplied externally (from settings.ENCRYPTION_KEY) — never hard-coded.

Key management:
- Accepts a 32-byte key (256 bits for AES-256).
- ENCRYPTION_KEY is required for encryption operations in every environment.
- Generate it as base64url(os.urandom(32)) and configure it before startup.
- Production SHOULD use a KMS (AWS KMS, GCP KMS, Azure Key Vault) for
  key management, rotation, and audit trails.

NOT zero-knowledge: the server holds the key and can decrypt credentials.
Zero-knowledge architecture is documented as a future enhancement.

NEVER:
- Log or return the plaintext password.
- Log or return the encryption key.
- Hard-code the key.
- Reuse nonces (each encrypt() generates a fresh random nonce).
- Use ECB, CBC without integrity verification, or any custom algorithm.
"""
import base64
import logging
import os

from cryptography.exceptions import InvalidTag  # noqa: F401 — re-exported for callers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

logger = logging.getLogger(__name__)

_NONCE_BYTES = 12  # 96-bit nonce — GCM recommended size
_KEY_BYTES = 32    # 256 bits — AES-256


class EncryptionError(Exception):
    """Raised when encryption or decryption fails.

    The original exception is logged at WARNING level but is NOT propagated
    to API responses to avoid leaking internal details.
    """


class EncryptionService:
    """AES-256-GCM symmetric encryption for credential passwords.

    Instantiate via get_encryption_service() for production use.
    Instantiate directly with a test key in unit tests.
    """

    def __init__(self, key: bytes) -> None:
        """
        Args:
            key: Exactly 32 bytes (256 bits). Any other length raises ValueError.
        """
        if len(key) != _KEY_BYTES:
            raise ValueError(
                f"AES-256-GCM requires a {_KEY_BYTES}-byte key; got {len(key)} bytes."
            )
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext password string.

        Returns:
            A base64url-encoded string: nonce(12) ‖ ciphertext ‖ tag(16).

        Raises:
            EncryptionError: if encryption fails for any reason.

        NEVER:
            - Log the plaintext argument.
            - Return the key.
            - Reuse nonces (each call generates a fresh random nonce).
        """
        try:
            nonce = os.urandom(_NONCE_BYTES)
            # AESGCM.encrypt appends the 16-byte GCM tag to the ciphertext.
            ciphertext_with_tag = self._aesgcm.encrypt(
                nonce, plaintext.encode("utf-8"), None
            )
            combined = nonce + ciphertext_with_tag
            return base64.urlsafe_b64encode(combined).decode("ascii")
        except Exception as exc:
            logger.warning("Encryption failed: %s", type(exc).__name__)
            raise EncryptionError("Encryption failed.") from exc

    def decrypt(self, encrypted: str) -> str:
        """Decrypt an AES-256-GCM ciphertext produced by encrypt().

        Returns:
            The plaintext password string.

        Raises:
            EncryptionError: if decryption fails.
            cryptography.exceptions.InvalidTag: (wrapped in EncryptionError)
                if the ciphertext was tampered with or the key is wrong.

        NEVER:
            - Log the return value (it is the plaintext password).
        """
        try:
            raw = base64.urlsafe_b64decode(encrypted.encode("ascii"))
            if len(raw) < _NONCE_BYTES + 16:  # must have at least nonce + tag
                raise ValueError("Ciphertext is too short to be valid.")
            nonce = raw[:_NONCE_BYTES]
            ciphertext_with_tag = raw[_NONCE_BYTES:]
            # decrypt raises InvalidTag on tampered data — DO NOT CATCH IT silently.
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag:
            logger.warning(
                "Decryption failed: authentication tag mismatch — "
                "possible data tampering or wrong key."
            )
            raise EncryptionError(
                "Decryption failed: authentication verification failed."
            )
        except Exception as exc:
            logger.warning("Decryption failed: %s", type(exc).__name__)
            raise EncryptionError("Decryption failed.") from exc


# ── Factory ───────────────────────────────────────────────────────────────────

_enc_service: "EncryptionService | None" = None


def get_encryption_service() -> EncryptionService:
    """Return the module-level EncryptionService singleton.

    ENCRYPTION_KEY must be a non-empty base64url-encoded 32-byte value.
    Missing or malformed configuration fails closed; no key is generated or
    substituted at runtime.

    NOTE: Production deployments should store ENCRYPTION_KEY in a secrets manager
    (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) and consider rotating
    keys via envelope encryption with a KMS.
    """
    global _enc_service
    if _enc_service is None:
        _enc_service = _build_service()
    return _enc_service


def _build_service() -> EncryptionService:
    key_b64 = getattr(settings, "ENCRYPTION_KEY", "")
    if not key_b64:
        raise EncryptionError(
            "ENCRYPTION_KEY must be configured before credential encryption can run."
        )

    try:
        key = base64.urlsafe_b64decode(key_b64.encode("ascii"))
    except Exception:
        raise EncryptionError(
            "ENCRYPTION_KEY must be a valid base64url-encoded 32-byte key."
        )

    if len(key) != _KEY_BYTES:
        raise EncryptionError(
            f"ENCRYPTION_KEY must decode to exactly {_KEY_BYTES} bytes."
        )

    return EncryptionService(key=key)


def make_test_encryption_service() -> EncryptionService:
    """Return an EncryptionService with a deterministic test key.

    FOR TESTS ONLY. Never call this in production code.
    The test key is a fixed 32-byte sequence — clearly not a real key.
    """
    return EncryptionService(key=b"\x01" * _KEY_BYTES)
