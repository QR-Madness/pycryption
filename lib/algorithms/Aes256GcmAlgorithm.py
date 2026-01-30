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
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lib.EncryptionAlgorithm import (
    AlgorithmAdapter,
    EncryptionAlgorithm,
    EncryptionInput,
    EncryptionOutput,
)
from lib.util.kms.providers import KeyProvider, inject_key


# -----------------------------------------------------------------------------
# Input/Output Classes
# -----------------------------------------------------------------------------


class Aes256GcmInput(EncryptionInput):
    """Input payload for AES-256-GCM encryption."""

    associated_data: Optional[bytes]

    def __init__(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ):
        super().__init__(data=plaintext)
        self.associated_data = associated_data

    @property
    def plaintext(self) -> bytes:
        return self.data


class Aes256GcmOutput(EncryptionOutput):
    """Output payload from AES-256-GCM operations."""

    nonce: bytes
    associated_data: Optional[bytes]

    def __init__(
        self,
        ciphertext: bytes,
        nonce: bytes,
        metrics: Optional[dict] = None,
        associated_data: Optional[bytes] = None,
    ):
        super().__init__(data=ciphertext, metrics=metrics or {})
        self.nonce = nonce
        self.associated_data = associated_data

    @property
    def ciphertext(self) -> bytes:
        return self.data


# -----------------------------------------------------------------------------
# Notebook Adapter
# -----------------------------------------------------------------------------


class Aes256GcmAdapter(AlgorithmAdapter):
    """Adapter for marshalling bytes <-> Aes256GcmInput/Output."""

    def prepare_encrypt_input(self, data: bytes) -> Aes256GcmInput:
        return Aes256GcmInput(plaintext=data)

    def extract_encrypt_output(self, output: Aes256GcmOutput, state: dict) -> bytes:
        state["nonce"] = output.nonce
        return output.ciphertext

    def prepare_decrypt_input(self, data: bytes, state: dict) -> Aes256GcmOutput:
        return Aes256GcmOutput(
            ciphertext=data,
            nonce=state["nonce"],
        )

    def extract_decrypt_output(self, output: EncryptionOutput) -> bytes:
        return output.data


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
        super().__init__()

    @classmethod
    def adapter(cls) -> Aes256GcmAdapter:
        """Return the adapter for bytes <-> structured I/O conversion."""
        return Aes256GcmAdapter()

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
        payload: EncryptionInput,
        *,
        _injected_key: Optional[bytes] = None,
    ) -> EncryptionOutput:
        """
        Encrypt plaintext using AES-256-GCM.

        Key is automatically injected by @inject_key decorator.
        """
        if not isinstance(payload, Aes256GcmInput):
            raise TypeError(f"Expected Aes256GcmInput, got {type(payload).__name__}")

        start = time.perf_counter()

        key = _injected_key or self._get_key()

        aesgcm = AESGCM(key)
        nonce = self._generate_nonce()
        ciphertext = aesgcm.encrypt(nonce, payload.plaintext, payload.associated_data)

        elapsed_ms = (time.perf_counter() - start) * 1000

        return Aes256GcmOutput(
            ciphertext=ciphertext,
            nonce=nonce,
            metrics={
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
        payload: EncryptionOutput,
        *,
        _injected_key: Optional[bytes] = None,
    ) -> EncryptionOutput:
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

        return EncryptionOutput(
            data=plaintext,
            metrics={
                "algorithm": "AES-256-GCM",
                "operation": "decrypt",
                "ciphertext_bytes": len(payload.ciphertext),
                "plaintext_bytes": len(plaintext),
                "elapsed_ms": round(elapsed_ms, 3),
            },
        )


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
    from lib.util.kms.providers import LocalKeyProvider

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
    from lib.util.kms.providers import DerivedKeyProvider

    algo = Aes256GcmAlgorithm()
    algo._key_provider = DerivedKeyProvider(
        password=password,
        salt=salt,
        key_length=32,
        kdf="pbkdf2",
        iterations=iterations,
    )
    return algo
