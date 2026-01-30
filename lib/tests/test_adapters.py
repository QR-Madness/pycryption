# lib/tests/test_adapters.py
"""Tests for the adapter factory and backward-compatible wrappers."""
import pytest

from lib.algorithms import Aes256GcmAdapter, Aes256GcmAlgorithm
from lib.EncryptionAlgorithm import EncryptionAlgorithm
from lib.notebook.adapters import adapt, wrap_aes256gcm
from lib.notebook.composer import ComposerSession
from lib.notebook.utils import generate_key
from lib.util.kms.providers import LocalKeyProvider


@pytest.fixture
def key() -> bytes:
    return generate_key(32)


class TestAdapt:
    """Tests for the generic adapt() factory."""

    def test_round_trip(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="Test-AES")

        plaintext = b"Hello, PyCryption!"
        enc = algo.encrypt(plaintext)
        assert enc.success
        assert enc.output != plaintext

        dec = algo.decrypt(enc.output)
        assert dec.success
        assert dec.output == plaintext

    def test_default_name_from_class(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key)
        result = algo.encrypt(b"test")
        assert result.metrics["algorithm"] == "Aes256GcmAlgorithm"

    def test_custom_name(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="My-AES")
        result = algo.encrypt(b"test")
        assert result.metrics["algorithm"] == "My-AES"

    def test_metrics_populated(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-Metrics")
        result = algo.encrypt(b"test data")
        assert result.success
        assert "elapsed_ms" in result.metrics
        assert result.metrics["algorithm"] == "AES-Metrics"
        assert result.metrics["operation"] == "encrypt"
        assert result.metrics["input_bytes"] > 0
        assert result.metrics["output_bytes"] > 0

    def test_key_provider_passthrough(self, key: bytes) -> None:
        provider = LocalKeyProvider(key)
        algo = adapt(Aes256GcmAlgorithm, provider, name="AES-Provider")

        enc = algo.encrypt(b"provider test")
        dec = algo.decrypt(enc.output)
        assert dec.output == b"provider test"

    def test_explicit_adapter_override(self, key: bytes) -> None:
        algo = adapt(
            Aes256GcmAlgorithm,
            key,
            name="AES-Explicit",
            adapter=Aes256GcmAdapter(),
        )

        enc = algo.encrypt(b"explicit adapter test")
        dec = algo.decrypt(enc.output)
        assert dec.output == b"explicit adapter test"

    def test_missing_adapter_raises_type_error(self, key: bytes) -> None:
        with pytest.raises(TypeError, match="does not have an adapter"):
            adapt(EncryptionAlgorithm, key, name="NoAdapter")

    def test_multiple_round_trips(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-Multi")

        for msg in [b"first", b"second", b"third"]:
            enc = algo.encrypt(msg)
            dec = algo.decrypt(enc.output)
            assert dec.output == msg

    def test_large_payload(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-Large")
        plaintext = b"x" * 100_000

        enc = algo.encrypt(plaintext)
        dec = algo.decrypt(enc.output)
        assert dec.output == plaintext


class TestWrapAes256Gcm:
    """Backward compatibility tests for wrap_aes256gcm."""

    def test_round_trip(self, key: bytes) -> None:
        algo = wrap_aes256gcm(key)

        plaintext = b"backward compat test"
        enc = algo.encrypt(plaintext)
        assert enc.success

        dec = algo.decrypt(enc.output)
        assert dec.success
        assert dec.output == plaintext

    def test_default_name(self, key: bytes) -> None:
        algo = wrap_aes256gcm(key)
        result = algo.encrypt(b"test")
        assert result.metrics["algorithm"] == "AES-256-GCM"

    def test_custom_name(self, key: bytes) -> None:
        algo = wrap_aes256gcm(key, name="Custom-AES")
        result = algo.encrypt(b"test")
        assert result.metrics["algorithm"] == "Custom-AES"


class TestComposerSessionIntegration:
    """Tests that adapted algorithms integrate with ComposerSession."""

    def test_register_and_test_all(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(adapt(Aes256GcmAlgorithm, key, name="AES-Adapted"))

        results = session.test_all()
        assert results["AES-Adapted"] is True

    def test_benchmark(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(adapt(Aes256GcmAlgorithm, key, name="AES-Bench"))

        benchmarks = session.benchmark("AES-Bench", data_sizes=[100, 1000], iterations=3)
        assert "benchmarks" in benchmarks
        assert len(benchmarks["benchmarks"]) == 2
