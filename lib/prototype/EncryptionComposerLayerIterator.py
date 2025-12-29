from lib.prototype.MultiEncryptionComposerLayer import MultiEncryptionComposerLayer


class EncryptionComposerLayerIterator:
    """
    Iterator for traversing encryption algorithm layers.
    """

    _layers: list[MultiEncryptionComposerLayer]
    _current_index: int = 0

    def __init__(self, layers: list[MultiEncryptionComposerLayer]):
        self._layers = layers

    def reset(self, layers: list[MultiEncryptionComposerLayer]):
        self._layers = layers
        self._current_index = 0

    def __iter__(self):
        return self

    def __next__(self) -> MultiEncryptionComposerLayer:
        if self._current_index < len(self._layers):
            layer = self._layers[self._current_index]
            self._current_index += 1
            return layer
        else:
            raise StopIteration
