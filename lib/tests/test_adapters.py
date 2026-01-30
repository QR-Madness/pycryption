# lib/tests/test_adapters.py
"""Tests for the adapter factory."""
import pytest

from lib.algorithms import Aes256GcmAdapter, Aes256GcmAlgorithm
from lib.EncryptionAlgorithm import EncryptionAlgorithm
from lib.notebook.adapters import adapt
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


class TestAdaptMemoryProfiling:
    """Tests for memory profiling and metrics on adapted algorithms."""

    def test_adapt_with_profile_memory(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-Mem", profile_memory=True)
        result = algo.encrypt(b"test data")
        assert result.success
        assert "peak_memory_bytes" in result.metrics
        assert result.metrics["peak_memory_bytes"] >= 0
        assert "memory_delta_bytes" in result.metrics
        assert result.metrics.get("memory_profiling") is True

    def test_adapt_without_profile_memory(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-NoMem")
        result = algo.encrypt(b"test data")
        assert result.success
        assert "peak_memory_bytes" not in result.metrics

    def test_adapt_with_collect_metrics(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-Det", collect_metrics=True)
        result = algo.encrypt(b"test data")
        assert result.success
        assert result.metrics.get("detailed") is True
        assert "timestamp" in result.metrics

    def test_adapt_full_stack(self, key: bytes) -> None:
        algo = adapt(
            Aes256GcmAlgorithm,
            key,
            name="AES-Full",
            profile_memory=True,
            collect_metrics=True,
        )
        result = algo.encrypt(b"test data")
        assert result.success
        assert "peak_memory_bytes" in result.metrics
        assert result.metrics.get("memory_profiling") is True
        assert result.metrics.get("detailed") is True
        assert "timestamp" in result.metrics
        assert "elapsed_ms" in result.metrics
        assert "expansion_ratio" in result.metrics

    def test_decrypt_also_profiled(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-DecMem", profile_memory=True)
        enc = algo.encrypt(b"test")
        dec = algo.decrypt(enc.output)
        assert dec.success
        assert "peak_memory_bytes" in dec.metrics

    def test_round_trip_with_profiling(self, key: bytes) -> None:
        algo = adapt(Aes256GcmAlgorithm, key, name="AES-RT", profile_memory=True)
        plaintext = b"round-trip with memory profiling"
        enc = algo.encrypt(plaintext)
        dec = algo.decrypt(enc.output)
        assert dec.output == plaintext


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

    def test_session_with_memory_profiling(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(
            adapt(Aes256GcmAlgorithm, key, name="AES-MemSess", profile_memory=True)
        )
        session.encrypt("AES-MemSess", b"test")

        report = session.report()
        assert "avg_peak_encrypt_memory_bytes" in report["AES-MemSess"]
