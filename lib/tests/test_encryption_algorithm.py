"""Tests for the unified base types and EncryptionAlgorithm ABC."""
import pytest

from lib.EncryptionAlgorithm import (
    EncryptionAlgorithm,
    EncryptionInput,
    EncryptionOutput,
)


class TestEncryptionInput:
    def test_data_field(self) -> None:
        inp = EncryptionInput(data=b"hello")
        assert inp.data == b"hello"

    def test_metadata_defaults_empty(self) -> None:
        inp = EncryptionInput(data=b"")
        assert inp.metadata == {}

    def test_metadata_custom(self) -> None:
        inp = EncryptionInput(data=b"x", metadata={"key": "value"})
        assert inp.metadata == {"key": "value"}

    def test_instances_do_not_share_metadata(self) -> None:
        a = EncryptionInput(data=b"a")
        b = EncryptionInput(data=b"b")
        a.metadata["only_a"] = True
        assert "only_a" not in b.metadata


class TestEncryptionOutput:
    def test_data_field(self) -> None:
        out = EncryptionOutput(data=b"ciphertext")
        assert out.data == b"ciphertext"

    def test_metrics_defaults_empty(self) -> None:
        out = EncryptionOutput(data=b"")
        assert out.metrics == {}

    def test_metadata_defaults_empty(self) -> None:
        out = EncryptionOutput(data=b"")
        assert out.metadata == {}

    def test_custom_metrics_and_metadata(self) -> None:
        out = EncryptionOutput(
            data=b"ct",
            metrics={"elapsed_ms": 1.5},
            metadata={"nonce": b"abc"},
        )
        assert out.metrics["elapsed_ms"] == 1.5
        assert out.metadata["nonce"] == b"abc"

    def test_instances_do_not_share_mutable_fields(self) -> None:
        a = EncryptionOutput(data=b"a")
        b = EncryptionOutput(data=b"b")
        a.metrics["only_a"] = True
        a.metadata["only_a"] = True
        assert "only_a" not in b.metrics
        assert "only_a" not in b.metadata


class TestEncryptionAlgorithmABC:
    def test_cannot_instantiate_base_class(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            EncryptionAlgorithm()  # type: ignore[abstract]

    def test_subclass_must_implement_encrypt_and_decrypt(self) -> None:
        class Incomplete(EncryptionAlgorithm):
            pass

        with pytest.raises(TypeError, match="abstract"):
            Incomplete()  # type: ignore[abstract]

    def test_subclass_with_both_methods_works(self) -> None:
        class Complete(EncryptionAlgorithm):
            def encrypt(self, payload):
                return EncryptionOutput(data=payload.data)

            def decrypt(self, payload):
                return EncryptionOutput(data=payload.data)

        algo = Complete()
        inp = EncryptionInput(data=b"test")
        enc = algo.encrypt(inp)
        assert enc.data == b"test"

        dec = algo.decrypt(enc)
        assert dec.data == b"test"
