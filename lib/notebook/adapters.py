# lib/notebook/adapters.py
"""
Adapters to bridge lib/algorithms implementations with the notebook API.

The lib/algorithms implementations use structured Input/Output objects,
while the notebook API uses raw bytes. These adapters wrap the proven
implementations to make them compatible with ComposerSession.
"""
from __future__ import annotations

from lib.notebook.context import AlgorithmResult
from lib.notebook.decorators import algorithm, with_key
from lib.algorithms import (
    Aes256GcmAlgorithm,
    Aes256GcmInput,
    Aes256GcmOutput,
    create_aes256gcm,
)


def wrap_aes256gcm(key: bytes, name: str = "AES-256-GCM") -> object:
    """
    Wrap the proven AES-256-GCM implementation for notebook API.

    Args:
        key: 32-byte encryption key
        name: Algorithm name for registration

    Returns:
        Notebook-compatible algorithm instance
    """
    inner = create_aes256gcm(key)

    @algorithm(name)
    @with_key(key)
    class WrappedAes256Gcm:
        """Notebook adapter for lib/algorithms Aes256GcmAlgorithm."""

        def encrypt(self, data: bytes, ctx) -> bytes:
            payload = Aes256GcmInput(plaintext=data)
            result = inner.encrypt(payload)
            # Store nonce in registry for decryption
            ctx.set_nonce("aes-nonce", result.nonce)
            return result.ciphertext

        def decrypt(self, data: bytes, ctx) -> bytes:
            nonce = ctx.get_nonce("aes-nonce")
            payload = Aes256GcmOutput(
                ciphertext=data,
                nonce=nonce,
                metrics_report={},
            )
            result = inner.decrypt(payload)
            return result.plaintext

    return WrappedAes256Gcm()
