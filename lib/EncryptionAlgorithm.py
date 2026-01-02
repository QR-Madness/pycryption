from typing import Literal, Union


MULTI_COMPOSER_TYPE = "multi"
SIMPLE_COMPOSER_TYPE = "simple"


class SimpleEncryptionAlgorithmOutput:
    """
    *Belongs to*: SimpleEncryptionComposer.py

    Override this class to define the output structure for encryption algorithms.
    """

    metrics_report: dict
    output: bytes

    def __init__(self, metrics_report: dict, output: bytes):
        self.metrics_report = metrics_report
        self.output = output


class SimpleEncryptionAlgorithmInput:
    """
    *Belongs to*: SimpleEncryptionComposer.py

    Override this class to define the input structure for encryption algorithms.
    """

    _composer_type = "simple"
    _is_decrypted: bool

    def __init__(self):
        pass
    


class MultiEncryptionAlgorithmOutput:
    """
    *Belongs to*: MultiEncryptionComposer.py

    Override this class to define the output structure for encryption algorithms.
    """

    def __init__(self):
        pass


class MultiEncryptionAlgorithmInput:
    """
    *Belongs to*: MultiEncryptionComposer.py

    Override this class to define the input structure for encryption algorithms.
    """

    _composer_type = "multi"

    def __init__(self):
        pass


class EncryptionAlgorithm:
    """
    Base class for all encryption algorithms.
    """

    _composer_type: str

    def __init__(self, composer_type: Literal["multi", "simple"]):
        """
        Initializes the encryption algorithm with the specified composer type.

        :param composer_type: Used to specify the type of composer. Multi-layer or simple (single algorithm).
        :type composer_type: Literal["multi", "simple"]
        """
        self._composer_type = composer_type

    def InjectKey(self, func):
        """
        Decorator to inject key handling logic into encryption/decryption methods.
        """
        def wrapper(*args, **kwargs):
            # Key injection logic can be implemented here
            return func(*args, **kwargs)
        return wrapper

    def encrypt(
        self,
        payload: Union[MultiEncryptionAlgorithmInput, SimpleEncryptionAlgorithmInput],
    ) -> Union[MultiEncryptionAlgorithmOutput, SimpleEncryptionAlgorithmOutput]:
        raise NotImplementedError("Encrypt method must be implemented by subclasses.")

    def decrypt(
        self,
        payload: Union[MultiEncryptionAlgorithmOutput, SimpleEncryptionAlgorithmOutput],
    ) -> Union[MultiEncryptionAlgorithmOutput, SimpleEncryptionAlgorithmOutput]:
        raise NotImplementedError("Decrypt method must be implemented by subclasses.")
