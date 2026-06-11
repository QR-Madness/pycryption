"""Tests for the output quality analysis suite (lib/notebook/analysis.py)."""
import os
import random

import pytest

from lib.algorithms import Aes256GcmAlgorithm
from lib.notebook import (
    AlgorithmContext,
    ComposerSession,
    adapt,
    algorithm,
    analyze_output,
    avalanche_effect,
    bit_difference_ratio,
    chi_squared_uniformity,
    ecb_canary,
    shannon_entropy,
    with_key,
)
from lib.notebook.analysis import AVALANCHE_HEALTHY_RANGE, min_expected_entropy

KEY = os.urandom(32)

# Deterministic "random" sample so chi-squared tests can't flake (a true
# random sample legitimately fails alpha=0.05 once in 20 runs).
UNIFORM_SAMPLE = bytes(range(256)) * 64
SEEDED_RANDOM_SAMPLE = random.Random(0xC0FFEE).randbytes(65536)


@algorithm("XOR-Prototype")
@with_key(KEY)
class XorPrototype:
    """Deterministic repeating-key XOR — the analysis suite's tackling dummy."""

    def encrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        key = ctx.key
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def decrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        return self.encrypt(data, ctx)


@algorithm("ECB-Prototype")
@with_key(KEY)
class EcbPrototype:
    """AES-256-ECB — exists to prove the canary catches block repetition."""

    def _cipher(self, ctx: AlgorithmContext):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        return Cipher(algorithms.AES(ctx.key), modes.ECB())

    def encrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        enc = self._cipher(ctx).encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        dec = self._cipher(ctx).decryptor()
        return dec.update(data) + dec.finalize()


@pytest.fixture
def aes():
    return adapt(Aes256GcmAlgorithm, KEY, name="AES-256-GCM")


class TestMinExpectedEntropy:
    def test_scales_with_sample_size(self) -> None:
        # bigger samples demand entropy closer to 8
        assert min_expected_entropy(1024) < min_expected_entropy(4096) < 8.0

    def test_capped_below_eight(self) -> None:
        assert min_expected_entropy(10**9) == 7.97

    def test_clean_cipher_clears_threshold_at_small_sizes(self) -> None:
        # 2KB random sample's expected entropy (~7.91) must clear its own bar
        sample = random.Random(7).randbytes(2048)
        assert shannon_entropy(sample) >= min_expected_entropy(2048)


class TestShannonEntropy:
    def test_empty_is_zero(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_constant_data_is_zero(self) -> None:
        assert shannon_entropy(bytes(4096)) == 0.0

    def test_perfectly_uniform_is_eight(self) -> None:
        assert shannon_entropy(UNIFORM_SAMPLE) == pytest.approx(8.0)

    def test_random_sample_is_high(self) -> None:
        assert shannon_entropy(SEEDED_RANDOM_SAMPLE) > 7.99

    def test_ascii_text_is_low(self) -> None:
        text = b"the quick brown fox jumps over the lazy dog " * 100
        assert shannon_entropy(text) < 5.0


class TestChiSquaredUniformity:
    def test_uniform_sample_passes(self) -> None:
        result = chi_squared_uniformity(UNIFORM_SAMPLE)
        assert result["uniform"] is True
        assert result["statistic"] == 0.0

    def test_seeded_random_passes(self) -> None:
        assert chi_squared_uniformity(SEEDED_RANDOM_SAMPLE)["uniform"] is True

    def test_skewed_sample_fails(self) -> None:
        skewed = bytes([0, 1]) * 2048
        result = chi_squared_uniformity(skewed)
        assert result["uniform"] is False
        assert result["statistic"] > result["critical_value"]


class TestBitDifferenceRatio:
    def test_identical(self) -> None:
        assert bit_difference_ratio(b"abc", b"abc") == 0.0

    def test_complement_is_hundred(self) -> None:
        a = bytes(64)
        b = bytes([0xFF]) * 64
        assert bit_difference_ratio(a, b) == 100.0

    def test_single_bit(self) -> None:
        a = bytes(8)
        b = bytes([1]) + bytes(7)
        assert bit_difference_ratio(a, b) == pytest.approx(100 / 64)


class TestAvalancheEffect:
    def test_aes_gcm_is_healthy(self, aes) -> None:
        pct = avalanche_effect(aes, sample_size=512, trials=8)
        assert AVALANCHE_HEALTHY_RANGE[0] <= pct <= AVALANCHE_HEALTHY_RANGE[1]

    def test_xor_prototype_is_busted(self) -> None:
        pct = avalanche_effect(XorPrototype(), sample_size=512, trials=8)
        # one flipped plaintext bit flips exactly one ciphertext bit
        assert pct < 1.0


class TestEcbCanary:
    def test_aes_gcm_is_clean(self, aes) -> None:
        result = ecb_canary(aes)
        assert result["clean"] is True

    def test_ecb_mode_is_caught(self) -> None:
        result = ecb_canary(EcbPrototype())
        assert result["clean"] is False
        # 64 identical plaintext blocks -> 63 duplicate ciphertext blocks
        assert result["duplicate_blocks"] == 63


class TestAnalyzeOutput:
    def test_aes_gcm_panel_is_clean(self, aes) -> None:
        panel = analyze_output(aes, sample_size=4096, trials=8)
        assert panel["flags"] == []
        assert panel["entropy_bits_per_byte"] >= min_expected_entropy(4096)
        assert panel["ecb_duplicate_blocks"] == 0

    def test_xor_prototype_is_flagged(self) -> None:
        panel = analyze_output(XorPrototype(), sample_size=4096, trials=8)
        assert "weak-avalanche" in panel["flags"]

    def test_ecb_prototype_is_flagged(self) -> None:
        panel = analyze_output(EcbPrototype(), sample_size=4096, trials=8)
        assert "ecb-pattern" in panel["flags"]


class TestComposerIntegration:
    def test_analyze_all(self, aes) -> None:
        session = ComposerSession()
        session.register(aes)
        session.register(XorPrototype())

        results = session.analyze_all(sample_size=2048, trials=8)
        assert results["AES-256-GCM"]["flags"] == []
        assert "weak-avalanche" in results["XOR-Prototype"]["flags"]

    def test_analyze_does_not_pollute_session_metrics(self, aes) -> None:
        session = ComposerSession()
        session.register(aes)
        session.analyze("AES-256-GCM", sample_size=1024, trials=4)
        report = session.report()
        assert report["AES-256-GCM"]["encrypt_calls"] == 0
