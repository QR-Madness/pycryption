# lib/algorithms/__init__.py
"""
Encryption algorithm implementations.

Symmetric algorithms follow the KeyProvider pattern for decoupled key
management; KEM-based hybrids are keypair-based.
"""
from lib.algorithms.Aes256GcmAlgorithm import (
    Aes256GcmAdapter,
    Aes256GcmAlgorithm,
    Aes256GcmInput,
    Aes256GcmOutput,
    create_aes256gcm,
    create_aes256gcm_from_password,
)
from lib.algorithms.ChaCha20Poly1305Algorithm import (
    ChaCha20Poly1305Adapter,
    ChaCha20Poly1305Algorithm,
    ChaCha20Poly1305Input,
    ChaCha20Poly1305Output,
    create_chacha20poly1305,
    create_chacha20poly1305_from_password,
)
from lib.algorithms.MlKem768HybridAlgorithm import (
    MlKem768HybridAdapter,
    MlKem768HybridAlgorithm,
    MlKem768HybridInput,
    MlKem768HybridOutput,
    create_ml_kem_768_hybrid,
)

__all__ = [
    "Aes256GcmAdapter",
    "Aes256GcmAlgorithm",
    "Aes256GcmInput",
    "Aes256GcmOutput",
    "create_aes256gcm",
    "create_aes256gcm_from_password",
    "ChaCha20Poly1305Adapter",
    "ChaCha20Poly1305Algorithm",
    "ChaCha20Poly1305Input",
    "ChaCha20Poly1305Output",
    "create_chacha20poly1305",
    "create_chacha20poly1305_from_password",
    "MlKem768HybridAdapter",
    "MlKem768HybridAlgorithm",
    "MlKem768HybridInput",
    "MlKem768HybridOutput",
    "create_ml_kem_768_hybrid",
]
