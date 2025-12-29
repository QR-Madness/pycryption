from lib.prototype.MultiEncryptionComposerLayer import MultiEncryptionComposerLayer
from lib.prototype.EncryptionComposerLayerIterator import EncryptionComposerLayerIterator
from lib.EncryptionAlgorithm import EncryptionAlgorithm


class MultiEncryptionComposer:
    """
    WARNING: NOT STABLE YET!

    Powerful encryption composer that allows layering multiple encryption algorithms.
    """

    # TODO Key propagation techniques
    # TODO Layer timers
    # TODO Encryption report types

    _algorithm_layers: list[MultiEncryptionComposerLayer] = []
    _iterator: EncryptionComposerLayerIterator

    def __init__(self):
        pass

    def __next_algorithm_layer(self):
        return next(self._iterator)

    def add_encryption_algorithm(self, algorithm: EncryptionAlgorithm):
        self._algorithm_layers.append(MultiEncryptionComposerLayer(algorithm))
        self._iterator = EncryptionComposerLayerIterator(self._algorithm_layers)

    def encrypt(self, payload):
        pass
