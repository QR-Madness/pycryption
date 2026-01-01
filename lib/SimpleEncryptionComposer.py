import time
from dataclasses import dataclass
from typing import Optional

from lib.EncryptionAlgorithm import (
    EncryptionAlgorithm,
    SIMPLE_COMPOSER_TYPE,
    SimpleEncryptionAlgorithmInput,
    SimpleEncryptionAlgorithmOutput,
)


class ComposerNotBootstrappedError(RuntimeError):
    """Raised when an operation is attempted before an algorithm is configured."""


class ComposerTypeMismatchError(RuntimeError):
    """Raised when a non-simple algorithm is provided to the simple composer."""


@dataclass
class SimpleComposerMetrics:
    """Lightweight metrics captured per composer instance."""

    encrypt_calls: int = 0
    decrypt_calls: int = 0
    last_encrypt_ms: Optional[float] = None
    last_decrypt_ms: Optional[float] = None
    algorithm_name: Optional[str] = None


class SimpleEncryptionComposer:
    """Simple encryption composer that manages a single encryption algorithm."""

    _algorithm: Optional[EncryptionAlgorithm]
    _metrics: SimpleComposerMetrics

    def __init__(self) -> None:
        self._algorithm = None
        self._metrics = SimpleComposerMetrics()

    def bootstrap(self, algorithm: EncryptionAlgorithm) -> None:
        """Attach a simple-mode encryption algorithm to this composer."""
        if not isinstance(algorithm, EncryptionAlgorithm):
            raise TypeError("algorithm must implement EncryptionAlgorithm")
        if getattr(algorithm, "_composer_type", None) != SIMPLE_COMPOSER_TYPE:
            raise ComposerTypeMismatchError(
                "SimpleEncryptionComposer requires a simple-mode algorithm",
            )
        self._algorithm = algorithm
        self._metrics.algorithm_name = algorithm.__class__.__name__

    def _ensure_bootstrapped(self) -> EncryptionAlgorithm:
        if self._algorithm is None:
            raise ComposerNotBootstrappedError("Composer has no configured algorithm")
        return self._algorithm

    def encrypt(
        self,
        payload: SimpleEncryptionAlgorithmInput,
    ) -> SimpleEncryptionAlgorithmOutput:
        """Encrypt the given payload using the configured algorithm."""
        algorithm = self._ensure_bootstrapped()
        start = time.perf_counter()
        result = algorithm.encrypt(payload)
        duration_ms = (time.perf_counter() - start) * 1000
        self._metrics.encrypt_calls += 1
        self._metrics.last_encrypt_ms = duration_ms
        if not isinstance(result, SimpleEncryptionAlgorithmOutput):
            raise TypeError("encrypt must return SimpleEncryptionAlgorithmOutput")
        return result

    def decrypt(
        self,
        payload: SimpleEncryptionAlgorithmOutput,
    ) -> SimpleEncryptionAlgorithmInput:
        """Decrypt the given payload using the configured algorithm."""
        algorithm = self._ensure_bootstrapped()
        start = time.perf_counter()
        result = algorithm.decrypt(payload)
        duration_ms = (time.perf_counter() - start) * 1000
        self._metrics.decrypt_calls += 1
        self._metrics.last_decrypt_ms = duration_ms
        if not isinstance(result, SimpleEncryptionAlgorithmInput):
            raise TypeError("decrypt must return SimpleEncryptionAlgorithmInput")
        return result

    def report(self) -> SimpleComposerMetrics:
        """Return captured metrics for observability and testing."""
        return self._metrics
