# lib/algorithms/ChaCha20Poly1305Algorithm.py
"""
ChaCha20-Poly1305 Algorithm Implementation.

The modern successor to Salsa20, standardized in RFC 8439. A stream cipher
with Poly1305 authentication — the primary AEAD alternative to AES-GCM,
preferred on platforms without AES hardware acceleration (AES-NI).

This module focuses purely on the cryptographic operations.
Key management is handled externally via KeyProvider decorators.

Usage:
    from lib.util.kms.providers import LocalKeyProvider, use_key_provider

    @use_key_provider(LocalKeyProvider(my_32_byte_key))
    class MyChaChaAlgorithm(ChaCha20Poly1305Algorithm):
        pass

    # Or configure at runtime:
    algo = ChaCha20Poly1305Algorithm()
    algo._key_provider = LocalKeyProvider(my_key)
"""
import os
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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


class ChaCha20Poly1305Input(EncryptionInput):
    """Input payload for ChaCha20-Poly1305 encryption."""

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


class ChaCha20Poly1305Output(EncryptionOutput):
    """Output payload from ChaCha20-Poly1305 operations."""

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


class ChaCha20Poly1305Adapter(AlgorithmAdapter):
    """Adapter for marshalling bytes <-> ChaCha20Poly1305Input/Output."""

    def prepare_encrypt_input(self, data: bytes) -> ChaCha20Poly1305Input:
        return ChaCha20Poly1305Input(plaintext=data)

    def extract_encrypt_output(self, output: ChaCha20Poly1305Output, state: dict) -> bytes:
        state["nonce"] = output.nonce
        return output.ciphertext

    def prepare_decrypt_input(self, data: bytes, state: dict) -> ChaCha20Poly1305Output:
        return ChaCha20Poly1305Output(
            ciphertext=data,
            nonce=state["nonce"],
        )

    def extract_decrypt_output(self, output: EncryptionOutput) -> bytes:
        return output.data


# -----------------------------------------------------------------------------
# Algorithm Implementation
# -----------------------------------------------------------------------------


class ChaCha20Poly1305Algorithm(EncryptionAlgorithm):
    """
    ChaCha20-Poly1305 authenticated encryption (RFC 8439).

    Key management is delegated to KeyProvider (set via decorator or runtime).
    This class focuses purely on the cryptographic operations.
    """

    NONCE_SIZE: int = 12  # 96 bits, per RFC 8439
    KEY_SIZE: int = 32    # 256 bits

    # Injected by @use_key_provider decorator or set manually
    _key_provider: Optional[KeyProvider] = None

    def __init__(self) -> None:
        super().__init__()

    @classmethod
    def adapter(cls) -> ChaCha20Poly1305Adapter:
        """Return the adapter for bytes <-> structured I/O conversion."""
        return ChaCha20Poly1305Adapter()

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
        Encrypt plaintext using ChaCha20-Poly1305.

        Key is automatically injected by @inject_key decorator.
        """
        if not isinstance(payload, ChaCha20Poly1305Input):
            raise TypeError(
                f"Expected ChaCha20Poly1305Input, got {type(payload).__name__}"
            )

        start = time.perf_counter()

        key = _injected_key or self._get_key()

        chacha = ChaCha20Poly1305(key)
        nonce = self._generate_nonce()
        ciphertext = chacha.encrypt(nonce, payload.plaintext, payload.associated_data)

        elapsed_ms = (time.perf_counter() - start) * 1000

        return ChaCha20Poly1305Output(
            ciphertext=ciphertext,
            nonce=nonce,
            metrics={
                "algorithm": "ChaCha20-Poly1305",
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
        Decrypt ciphertext using ChaCha20-Poly1305.

        Key is automatically injected by @inject_key decorator.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        if not isinstance(payload, ChaCha20Poly1305Output):
            raise TypeError(
                f"Expected ChaCha20Poly1305Output, got {type(payload).__name__}"
            )

        start = time.perf_counter()

        key = _injected_key or self._get_key()

        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(
            payload.nonce,
            payload.ciphertext,
            payload.associated_data,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return EncryptionOutput(
            data=plaintext,
            metrics={
                "algorithm": "ChaCha20-Poly1305",
                "operation": "decrypt",
                "ciphertext_bytes": len(payload.ciphertext),
                "plaintext_bytes": len(plaintext),
                "elapsed_ms": round(elapsed_ms, 3),
            },
        )


# -----------------------------------------------------------------------------
# Convenience factory for common configurations
# -----------------------------------------------------------------------------


def create_chacha20poly1305(key: bytes) -> ChaCha20Poly1305Algorithm:
    """
    Quick factory for creating ChaCha20-Poly1305 with a local key.

    Args:
        key: 32-byte encryption key

    Returns:
        Configured ChaCha20Poly1305Algorithm instance
    """
    from lib.util.kms.providers import LocalKeyProvider

    algo = ChaCha20Poly1305Algorithm()
    algo._key_provider = LocalKeyProvider(key)
    return algo


def create_chacha20poly1305_from_password(
    password: str,
    salt: bytes,
    iterations: int = 480000,
) -> ChaCha20Poly1305Algorithm:
    """
    Create ChaCha20-Poly1305 with key derived from password.

    Args:
        password: User password
        salt: Random salt (store alongside ciphertext)
        iterations: PBKDF2 iterations (default: OWASP 2023 recommendation)

    Returns:
        Configured ChaCha20Poly1305Algorithm instance
    """
    from lib.util.kms.providers import DerivedKeyProvider

    algo = ChaCha20Poly1305Algorithm()
    algo._key_provider = DerivedKeyProvider(
        password=password,
        salt=salt,
        key_length=32,
        kdf="pbkdf2",
        iterations=iterations,
    )
    return algo
