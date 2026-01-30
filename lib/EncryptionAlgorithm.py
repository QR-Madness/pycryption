from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class EncryptionInput:
    """
    Base input for all encryption algorithms.

    Subclasses add algorithm-specific fields (e.g., associated_data for GCM).
    The ``data`` field carries the raw plaintext bytes.
    """

    data: bytes
    metadata: dict = field(default_factory=dict)


@dataclass
class EncryptionOutput:
    """
    Base output from all encryption operations (encrypt and decrypt).

    The ``data`` field carries the primary payload (ciphertext after encrypt,
    plaintext after decrypt).  Algorithm-specific auxiliary data (nonces, tags,
    etc.) belongs on subclass fields or in ``metadata``.
    """

    data: bytes
    metrics: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


class EncryptionAlgorithm(ABC):
    """
    Base class for all encryption algorithms.

    Subclasses must implement ``encrypt`` and ``decrypt``.
    Key management is handled externally via KeyProvider.
    """

    @abstractmethod
    def encrypt(self, payload: EncryptionInput) -> EncryptionOutput:
        """Encrypt the payload and return an EncryptionOutput."""
        ...

    @abstractmethod
    def decrypt(self, payload: EncryptionOutput) -> EncryptionOutput:
        """Decrypt the payload and return an EncryptionOutput."""
        ...


class AlgorithmAdapter(ABC):
    """
    Defines how to convert between raw bytes and algorithm-specific
    structured Input/Output types.

    Each embedded algorithm provides a companion adapter that implements
    these four methods. The ``state`` dict is a dependency-free mechanism
    for persisting auxiliary data (nonces, IVs, tags, etc.) across
    encrypt/decrypt calls — the ``adapt()`` factory in ``lib/notebook``
    maps it to the CryptoRegistry automatically.
    """

    @abstractmethod
    def prepare_encrypt_input(self, data: bytes) -> EncryptionInput:
        """Convert raw plaintext bytes to algorithm-specific encrypt input."""

    @abstractmethod
    def extract_encrypt_output(self, output: EncryptionOutput, state: dict) -> bytes:
        """Extract ciphertext from output, store auxiliary data in *state*."""

    @abstractmethod
    def prepare_decrypt_input(self, data: bytes, state: dict) -> EncryptionOutput:
        """Build decrypt input from ciphertext and stored auxiliary data."""

    @abstractmethod
    def extract_decrypt_output(self, output: EncryptionOutput) -> bytes:
        """Extract plaintext from decrypt output."""
