# lib/algorithms/__init__.py
"""
Encryption algorithm implementations.

All algorithms follow the KeyProvider pattern for decoupled key management.
"""
from lib.algorithms.Aes256GcmAlgorithm import (
    Aes256GcmAdapter,
    Aes256GcmAlgorithm,
    Aes256GcmInput,
    Aes256GcmOutput,
    create_aes256gcm,
    create_aes256gcm_from_password,
)

__all__ = [
    "Aes256GcmAdapter",
    "Aes256GcmAlgorithm",
    "Aes256GcmInput",
    "Aes256GcmOutput",
    "create_aes256gcm",
    "create_aes256gcm_from_password",
]
