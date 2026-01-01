# lib/algorithms/Aes256GcmAlgorithm.py
"""
AES-256-GCM Algorithm Implementation.

This module focuses purely on the cryptographic operations.
Key management is handled externally via KeyProvider decorators.

Usage:
    from lib.util.key_providers import LocalKeyProvider, use_key_provider

    @use_key_provider(LocalKeyProvider(my_32_byte_key))
    class MyAesAlgorithm(Aes256GcmAlgorithm):
        pass

    # Or configure at runtime:
    algo = Aes256GcmAlgorithm()
    algo._key_provider = LocalKeyProvider(my_key)
"""
import os
import time
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lib.EncryptionAlgorithm import (
    EncryptionAlgorithm,
    SIMPLE_COMPOSER_TYPE,
    SimpleEncryptionAlgorithmInput,
    SimpleEncryptionAlgorithmOutput,
    MultiEncryptionAlgorithmInput,
    MultiEncryptionAlgorithmOutput,
)
from lib.util.key_providers import KeyProvider, inject_key


# -----------------------------------------------------------------------------
# Input/Output Classes
# -----------------------------------------------------------------------------


class Aes256GcmInput(SimpleEncryptionAlgorithmInput):
    """Input payload for AES-256-GCM encryption."""

    plaintext: bytes
    associated_data: Optional[bytes]
    metrics_report: Optional[dict]  # Set after decryption

    def __init__(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ):
        super().__init__()
        self.plaintext = plaintext
        self.associated_data = associated_data
        self.metrics_report = None


class Aes256GcmOutput(SimpleEncryptionAlgorithmOutput):
    """Output payload from AES-256-GCM encryption."""

    ciphertext: bytes
    nonce: bytes  # 12 bytes
    associated_data: Optional[bytes]

    def __init__(
        self,
        ciphertext: bytes,
        nonce: bytes,
        metrics_report: dict,
        associated_data: Optional[bytes] = None,
    ):
        super().__init__(metrics_report=metrics_report, output=ciphertext)
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.associated_data = associated_data


# -----------------------------------------------------------------------------
# Algorithm Implementation
# -----------------------------------------------------------------------------


class Aes256GcmAlgorithm(EncryptionAlgorithm):
    """
    AES-256-GCM authenticated encryption.

    Key management is delegated to KeyProvider (set via decorator or runtime).
    This class focuses purely on the cryptographic operations.
    """

    NONCE_SIZE: int = 12  # 96 bits, recommended for GCM
    KEY_SIZE: int = 32    # 256 bits

    # Injected by @use_key_provider decorator or set manually
    _key_provider: Optional[KeyProvider] = None

    def __init__(self) -> None:
        super().__init__(SIMPLE_COMPOSER_TYPE)

    def _generate_nonce(self) -> bytes:
        """Generate cryptographically secure random nonce."""
        return os.urandom(self.NONCE_SIZE)

    def _get_key(self) -> bytes:
        """Retrieve key from provider."""
        if self._key_provider is None:
            raise ValueError(
                "No key provider configured. "
                "Use @use_key_provider decorator or set _key_provider manually."
            )
        key = self._key_provider.get_key()
        self._key_provider.validate_key(key, self.KEY_SIZE)
        return key

    @inject_key(key_length=32)
    def encrypt(
        self,
        payload: Union[MultiEncryptionAlgorithmInput, SimpleEncryptionAlgorithmInput],
        *,
        _injected_key: Optional[bytes] = None,
    ) -> Union[MultiEncryptionAlgorithmOutput, SimpleEncryptionAlgorithmOutput]:
        """
        Encrypt plaintext using AES-256-GCM.

        Key is automatically injected by @inject_key decorator.
        """
        if not isinstance(payload, Aes256GcmInput):
            raise TypeError(f"Expected Aes256GcmInput, got {type(payload).__name__}")

        start = time.perf_counter()

        # Key injected by decorator
        key = _injected_key or self._get_key()

        aesgcm = AESGCM(key)
        nonce = self._generate_nonce()
        ciphertext = aesgcm.encrypt(nonce, payload.plaintext, payload.associated_data)

        elapsed_ms = (time.perf_counter() - start) * 1000

        return Aes256GcmOutput(
            ciphertext=ciphertext,
            nonce=nonce,
            metrics_report={
                "algorithm": "AES-256-GCM",
                "operation": "encrypt",
                "plaintext_bytes": len(payload.plaintext),
                "ciphertext_bytes": len(ciphertext),
                "elapsed_ms": round(elapsed_ms, 3),
            },
            associated_data=payload.associated_data,
        )

    @inject_key(key_length=32)
    def decrypt(
        self,
        payload: Union[MultiEncryptionAlgorithmOutput, SimpleEncryptionAlgorithmOutput],
        *,
        _injected_key: Optional[bytes] = None,
    ) -> Union[MultiEncryptionAlgorithmOutput, SimpleEncryptionAlgorithmOutput]:
        """
        Decrypt ciphertext using AES-256-GCM.

        Key is automatically injected by @inject_key decorator.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        if not isinstance(payload, Aes256GcmOutput):
            raise TypeError(f"Expected Aes256GcmOutput, got {type(payload).__name__}")

        start = time.perf_counter()

        key = _injected_key or self._get_key()

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(
            payload.nonce,
            payload.ciphertext,
            payload.associated_data,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        result = Aes256GcmInput(
            plaintext=plaintext,
            associated_data=payload.associated_data,
        )
        result._is_decrypted = True
        result.metrics_report = {
            "algorithm": "AES-256-GCM",
            "operation": "decrypt",
            "ciphertext_bytes": len(payload.ciphertext),
            "plaintext_bytes": len(plaintext),
            "elapsed_ms": round(elapsed_ms, 3),
        }

        return result  # type: ignore[return-value]


# -----------------------------------------------------------------------------
# Convenience factory for common configurations
# -----------------------------------------------------------------------------


def create_aes256gcm(key: bytes) -> Aes256GcmAlgorithm:
    """
    Quick factory for creating AES-256-GCM with a local key.

    Args:
        key: 32-byte encryption key

    Returns:
        Configured Aes256GcmAlgorithm instance
    """
    from lib.util.key_providers import LocalKeyProvider

    algo = Aes256GcmAlgorithm()
    algo._key_provider = LocalKeyProvider(key)
    return algo


def create_aes256gcm_from_password(
    password: str,
    salt: bytes,
    iterations: int = 480000,
) -> Aes256GcmAlgorithm:
    """
    Create AES-256-GCM with key derived from password.

    Args:
        password: User password
        salt: Random salt (store alongside ciphertext)
        iterations: PBKDF2 iterations (default: OWASP 2023 recommendation)

    Returns:
        Configured Aes256GcmAlgorithm instance
    """
    from lib.util.key_providers import DerivedKeyProvider

    algo = Aes256GcmAlgorithm()
    algo._key_provider = DerivedKeyProvider(
        password=password,
        salt=salt,
        key_length=32,
        kdf="pbkdf2",
        iterations=iterations,
    )
    return algo
