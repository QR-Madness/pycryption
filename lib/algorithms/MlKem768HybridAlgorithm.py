# lib/algorithms/MlKem768HybridAlgorithm.py
"""
ML-KEM-768 + AES-256-GCM Hybrid Algorithm Implementation.

A post-quantum KEM-DEM construction: ML-KEM-768 (FIPS 203, formerly
CRYSTALS-Kyber) encapsulates a fresh 32-byte shared secret against the
recipient's public key, and that secret keys AES-256-GCM as the data
encapsulation mechanism. This mirrors the real-world PQ migration pattern
(e.g., TLS hybrid key exchange).

Unlike the symmetric algorithms, key management is keypair-based rather
than KeyProvider-based: encryption needs only the public key, decryption
needs the secret key. A fresh keypair is generated when neither is supplied,
which keeps the no-arg constructor compatible with the notebook ``adapt()``
factory.

Note: the encapsulated shared secret is used directly as the AES-256 key.
ML-KEM's shared secret is uniformly random, so this is sound; production
designs frequently still pass it through HKDF for domain separation.

Usage:
    algo = create_ml_kem_768_hybrid()              # fresh keypair
    algo = MlKem768HybridAlgorithm(public_key=pk)  # encrypt-only

    out = algo.encrypt(MlKem768HybridInput(plaintext=b"msg"))
    pt = algo.decrypt(out).data
"""
import os
import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem import ml_kem_768

from lib.EncryptionAlgorithm import (
    AlgorithmAdapter,
    EncryptionAlgorithm,
    EncryptionInput,
    EncryptionOutput,
)


# -----------------------------------------------------------------------------
# Input/Output Classes
# -----------------------------------------------------------------------------


class MlKem768HybridInput(EncryptionInput):
    """Input payload for ML-KEM-768 hybrid encryption."""

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


class MlKem768HybridOutput(EncryptionOutput):
    """Output payload from ML-KEM-768 hybrid operations."""

    kem_ciphertext: bytes
    nonce: bytes
    associated_data: Optional[bytes]

    def __init__(
        self,
        ciphertext: bytes,
        kem_ciphertext: bytes,
        nonce: bytes,
        metrics: Optional[dict] = None,
        associated_data: Optional[bytes] = None,
    ):
        super().__init__(data=ciphertext, metrics=metrics or {})
        self.kem_ciphertext = kem_ciphertext
        self.nonce = nonce
        self.associated_data = associated_data

    @property
    def ciphertext(self) -> bytes:
        return self.data


# -----------------------------------------------------------------------------
# Notebook Adapter
# -----------------------------------------------------------------------------


class MlKem768HybridAdapter(AlgorithmAdapter):
    """Adapter for marshalling bytes <-> MlKem768HybridInput/Output."""

    def prepare_encrypt_input(self, data: bytes) -> MlKem768HybridInput:
        return MlKem768HybridInput(plaintext=data)

    def extract_encrypt_output(self, output: MlKem768HybridOutput, state: dict) -> bytes:
        state["kem_ciphertext"] = output.kem_ciphertext
        state["nonce"] = output.nonce
        return output.ciphertext

    def prepare_decrypt_input(self, data: bytes, state: dict) -> MlKem768HybridOutput:
        return MlKem768HybridOutput(
            ciphertext=data,
            kem_ciphertext=state["kem_ciphertext"],
            nonce=state["nonce"],
        )

    def extract_decrypt_output(self, output: EncryptionOutput) -> bytes:
        return output.data


# -----------------------------------------------------------------------------
# Algorithm Implementation
# -----------------------------------------------------------------------------


class MlKem768HybridAlgorithm(EncryptionAlgorithm):
    """
    ML-KEM-768 + AES-256-GCM hybrid encryption (KEM-DEM).

    Each encrypt() encapsulates a fresh shared secret, so every message is
    keyed independently — there is no long-lived symmetric key to manage.
    """

    NONCE_SIZE: int = 12  # 96 bits, recommended for GCM
    PUBLIC_KEY_SIZE: int = ml_kem_768.PUBLIC_KEY_SIZE    # 1184
    SECRET_KEY_SIZE: int = ml_kem_768.SECRET_KEY_SIZE    # 2400
    KEM_CIPHERTEXT_SIZE: int = ml_kem_768.CIPHERTEXT_SIZE  # 1088

    def __init__(
        self,
        public_key: Optional[bytes] = None,
        secret_key: Optional[bytes] = None,
    ) -> None:
        super().__init__()
        if public_key is None and secret_key is None:
            public_key, secret_key = ml_kem_768.generate_keypair()
        self.public_key = public_key
        self.secret_key = secret_key

    @classmethod
    def adapter(cls) -> MlKem768HybridAdapter:
        """Return the adapter for bytes <-> structured I/O conversion."""
        return MlKem768HybridAdapter()

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generate an ML-KEM-768 keypair as (public_key, secret_key)."""
        return ml_kem_768.generate_keypair()

    def _generate_nonce(self) -> bytes:
        """Generate cryptographically secure random nonce."""
        return os.urandom(self.NONCE_SIZE)

    def encrypt(self, payload: EncryptionInput) -> EncryptionOutput:
        """
        Encrypt plaintext by encapsulating a fresh shared secret against the
        public key, then sealing the data with AES-256-GCM under that secret.
        """
        if not isinstance(payload, MlKem768HybridInput):
            raise TypeError(
                f"Expected MlKem768HybridInput, got {type(payload).__name__}"
            )
        if self.public_key is None:
            raise ValueError("No public key configured; cannot encapsulate.")

        start = time.perf_counter()

        kem_ciphertext, shared_secret = ml_kem_768.encrypt(self.public_key)
        kem_elapsed_ms = (time.perf_counter() - start) * 1000

        aesgcm = AESGCM(shared_secret)
        nonce = self._generate_nonce()
        ciphertext = aesgcm.encrypt(nonce, payload.plaintext, payload.associated_data)

        elapsed_ms = (time.perf_counter() - start) * 1000

        return MlKem768HybridOutput(
            ciphertext=ciphertext,
            kem_ciphertext=kem_ciphertext,
            nonce=nonce,
            metrics={
                "algorithm": "ML-KEM-768+AES-256-GCM",
                "operation": "encrypt",
                "plaintext_bytes": len(payload.plaintext),
                "ciphertext_bytes": len(ciphertext),
                "kem_ciphertext_bytes": len(kem_ciphertext),
                "kem_elapsed_ms": round(kem_elapsed_ms, 3),
                "elapsed_ms": round(elapsed_ms, 3),
            },
            associated_data=payload.associated_data,
        )

    def decrypt(self, payload: EncryptionOutput) -> EncryptionOutput:
        """
        Decrypt by decapsulating the shared secret with the secret key,
        then opening the AES-256-GCM ciphertext.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        if not isinstance(payload, MlKem768HybridOutput):
            raise TypeError(
                f"Expected MlKem768HybridOutput, got {type(payload).__name__}"
            )
        if self.secret_key is None:
            raise ValueError("No secret key configured; cannot decapsulate.")

        start = time.perf_counter()

        shared_secret = ml_kem_768.decrypt(self.secret_key, payload.kem_ciphertext)
        kem_elapsed_ms = (time.perf_counter() - start) * 1000

        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(
            payload.nonce,
            payload.ciphertext,
            payload.associated_data,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return EncryptionOutput(
            data=plaintext,
            metrics={
                "algorithm": "ML-KEM-768+AES-256-GCM",
                "operation": "decrypt",
                "ciphertext_bytes": len(payload.ciphertext),
                "plaintext_bytes": len(plaintext),
                "kem_elapsed_ms": round(kem_elapsed_ms, 3),
                "elapsed_ms": round(elapsed_ms, 3),
            },
        )


# -----------------------------------------------------------------------------
# Convenience factory for common configurations
# -----------------------------------------------------------------------------


def create_ml_kem_768_hybrid(
    public_key: Optional[bytes] = None,
    secret_key: Optional[bytes] = None,
) -> MlKem768HybridAlgorithm:
    """
    Quick factory for creating the ML-KEM-768 hybrid.

    Args:
        public_key: Recipient public key (1184 bytes). Omit to generate.
        secret_key: Recipient secret key (2400 bytes). Omit to generate.

    Returns:
        Configured MlKem768HybridAlgorithm instance
    """
    return MlKem768HybridAlgorithm(public_key=public_key, secret_key=secret_key)
