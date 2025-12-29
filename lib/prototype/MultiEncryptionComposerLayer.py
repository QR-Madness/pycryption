from lib.EncryptionAlgorithm import EncryptionAlgorithm


import os


class MultiEncryptionComposerLayer:
    """
    Manages the encryption algorithm for a specific layer in the composer.
    """

    _layer_id: str
    _algorithm: EncryptionAlgorithm

    def __init__(self, algorithm: EncryptionAlgorithm):
        self._layer_id = os.urandom(8).decode("utf-8", "ignore")
        self._algorithm = algorithm
