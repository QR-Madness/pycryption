"""Tests for the Multi Encryption layered pipeline (lib/notebook/pipeline.py)."""
import os

import pytest

from lib.algorithms import (
    Aes256GcmAlgorithm,
    ChaCha20Poly1305Algorithm,
    MlKem768HybridAlgorithm,
)
from lib.notebook import (
    AlgorithmContext,
    ComposerSession,
    MultiEncryption,
    adapt,
    algorithm,
    with_key,
)

KEY_A = os.urandom(32)
KEY_B = os.urandom(32)


@algorithm("Failing")
class FailingAlgorithm:
    def encrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        raise RuntimeError("boom")

    def decrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        raise RuntimeError("boom")


@pytest.fixture
def pipeline() -> MultiEncryption:
    p = MultiEncryption(name="AES+ChaCha")
    p.add_layer(adapt(Aes256GcmAlgorithm, KEY_A, name="AES-256-GCM"))
    p.add_layer(adapt(ChaCha20Poly1305Algorithm, KEY_B, name="ChaCha20-Poly1305"))
    return p


class TestLayerManagement:
    def test_add_layer_chains(self) -> None:
        p = MultiEncryption()
        result = p.add_layer(adapt(Aes256GcmAlgorithm, KEY_A, name="AES"))
        assert result is p
        assert [l["name"] for l in p.layers()] == ["AES"]

    def test_layer_name_defaults_to_config_name(self) -> None:
        p = MultiEncryption()
        p.add_layer(adapt(Aes256GcmAlgorithm, KEY_A, name="AES-256-GCM"))
        assert p.layers()[0]["name"] == "AES-256-GCM"

    def test_duplicate_layer_name_raises(self, pipeline: MultiEncryption) -> None:
        with pytest.raises(ValueError, match="already exists"):
            pipeline.add_layer(adapt(Aes256GcmAlgorithm, KEY_A, name="AES-256-GCM"))

    def test_remove_layer(self, pipeline: MultiEncryption) -> None:
        pipeline.remove_layer("ChaCha20-Poly1305")
        assert [l["name"] for l in pipeline.layers()] == ["AES-256-GCM"]

    def test_remove_missing_layer_raises(self, pipeline: MultiEncryption) -> None:
        with pytest.raises(KeyError):
            pipeline.remove_layer("nope")

    def test_move_layer(self, pipeline: MultiEncryption) -> None:
        pipeline.move_layer("ChaCha20-Poly1305", 0)
        assert [l["name"] for l in pipeline.layers()] == ["ChaCha20-Poly1305", "AES-256-GCM"]

    def test_disable_enable(self, pipeline: MultiEncryption) -> None:
        pipeline.disable("AES-256-GCM")
        assert pipeline.layers()[0]["enabled"] is False
        pipeline.enable("AES-256-GCM")
        assert pipeline.layers()[0]["enabled"] is True


class TestRoundTrip:
    def test_two_layer_round_trip(self, pipeline: MultiEncryption) -> None:
        enc = pipeline.encrypt(b"layered secret")
        assert enc.success
        dec = pipeline.decrypt(enc.output)
        assert dec.success
        assert dec.output == b"layered secret"

    def test_ciphertext_differs_from_single_layer(self, pipeline: MultiEncryption) -> None:
        single = adapt(Aes256GcmAlgorithm, KEY_A, name="solo")
        layered = pipeline.encrypt(b"x" * 64)
        solo = single.encrypt(b"x" * 64)
        assert layered.output != solo.output

    def test_pq_hybrid_wrap_round_trip(self) -> None:
        # The flagship composition: classical AEAD wrapped in post-quantum hybrid
        p = MultiEncryption(name="PQ-Defense-In-Depth")
        p.add_layer(adapt(Aes256GcmAlgorithm, KEY_A, name="AES-256-GCM"))
        p.add_layer(adapt(MlKem768HybridAlgorithm, name="ML-KEM-768"))
        enc = p.encrypt(b"quantum-resistant onion")
        dec = p.decrypt(enc.output)
        assert dec.success
        assert dec.output == b"quantum-resistant onion"

    def test_disabled_layer_skipped_both_directions(self, pipeline: MultiEncryption) -> None:
        pipeline.disable("ChaCha20-Poly1305")
        enc = pipeline.encrypt(b"single hop")
        dec = pipeline.decrypt(enc.output)
        assert dec.output == b"single hop"
        assert enc.metrics["layer_count"] == 1

    def test_empty_pipeline_fails_cleanly(self) -> None:
        p = MultiEncryption()
        result = p.encrypt(b"data")
        assert not result.success
        assert "no enabled layers" in result.error

    def test_wrong_layer_order_fails_auth(self, pipeline: MultiEncryption) -> None:
        enc = pipeline.encrypt(b"order matters")
        pipeline.move_layer("AES-256-GCM", 1)  # reorder between enc and dec
        dec = pipeline.decrypt(enc.output)
        assert not dec.success  # AEAD auth must fail


class TestFailurePropagation:
    def test_failing_layer_aborts_pipeline(self) -> None:
        p = MultiEncryption()
        p.add_layer(adapt(Aes256GcmAlgorithm, KEY_A, name="AES"))
        p.add_layer(FailingAlgorithm())
        result = p.encrypt(b"data")
        assert not result.success
        assert "layer 'Failing' encrypt failed" in result.error
        # the successful first layer is still recorded
        assert result.metrics["layers"][0]["layer"] == "AES"


class TestMetrics:
    def test_per_layer_metrics(self, pipeline: MultiEncryption) -> None:
        enc = pipeline.encrypt(b"m" * 1000)
        layers = enc.metrics["layers"]
        assert [l["layer"] for l in layers] == ["AES-256-GCM", "ChaCha20-Poly1305"]
        for entry in layers:
            assert entry["elapsed_ms"] >= 0
            assert entry["output_bytes"] > entry["input_bytes"] - 1
            assert "expansion_ratio" in entry

    def test_aggregate_metrics(self, pipeline: MultiEncryption) -> None:
        enc = pipeline.encrypt(b"m" * 1000)
        assert enc.metrics["algorithm"] == "AES+ChaCha"
        assert enc.metrics["layer_count"] == 2
        assert enc.metrics["input_bytes"] == 1000
        # two AEAD layers -> two 16B tags + two 0-byte... expansion compounds
        assert enc.metrics["output_bytes"] == 1000 + 16 + 16
        assert enc.metrics["expansion_ratio"] == pytest.approx(1.032)

    def test_decrypt_layers_reversed_in_metrics(self, pipeline: MultiEncryption) -> None:
        enc = pipeline.encrypt(b"data")
        dec = pipeline.decrypt(enc.output)
        assert [l["layer"] for l in dec.metrics["layers"]] == ["ChaCha20-Poly1305", "AES-256-GCM"]


class TestComposerIntegration:
    def test_pipeline_registers_and_round_trips(self, pipeline: MultiEncryption) -> None:
        session = ComposerSession()
        session.register(pipeline)
        assert session.list_algorithms() == ["AES+ChaCha"]
        assert session.test("AES+ChaCha") is True

    def test_pipeline_benchmarks(self, pipeline: MultiEncryption) -> None:
        session = ComposerSession()
        session.register(pipeline)
        result = session.benchmark("AES+ChaCha", data_sizes=[256], iterations=3)
        assert result["benchmarks"][0]["avg_encrypt_ms"] >= 0

    def test_pipeline_passes_quality_analysis(self, pipeline: MultiEncryption) -> None:
        session = ComposerSession()
        session.register(pipeline)
        panel = session.analyze("AES+ChaCha", sample_size=2048, trials=4)
        assert panel["flags"] == []
