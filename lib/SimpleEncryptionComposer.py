from lib.EncryptionAlgorithm import (
    EncryptionAlgorithm,
    SimpleEncryptionAlgorithmInput,
    SimpleEncryptionAlgorithmOutput,
)


class SimpleEncryptionComposer:
    """
    Simple encryption composer that manages a single encryption algorithm.
    """

    _algorithm: EncryptionAlgorithm

    def __init__(self) -> None:
        pass

    def bootstrap(self, algorithm: EncryptionAlgorithm) -> None:
        """Bootstraps (no integration test) the composer with a specific encryption algorithm."""
        self._algorithm = algorithm

    def encrypt(
        self,
        payload: SimpleEncryptionAlgorithmInput,
    ) -> SimpleEncryptionAlgorithmOutput:
        """Encrypts the given payload using the configured encryption algorithm."""
        result = self._algorithm.encrypt(payload)
        assert isinstance(result, SimpleEncryptionAlgorithmOutput)
        return result

    def decrypt(
        self,
        payload: SimpleEncryptionAlgorithmOutput,
    ) -> SimpleEncryptionAlgorithmInput:
        """Decrypts the given payload using the configured encryption algorithm."""
        result = self._algorithm.decrypt(payload)
        assert isinstance(result, SimpleEncryptionAlgorithmInput)
        return result
