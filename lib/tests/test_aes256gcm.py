"""Direct tests for Aes256GcmAlgorithm (not through the adapter/notebook layer)."""
import os

import pytest

from lib.EncryptionAlgorithm import EncryptionOutput
from lib.algorithms import (
    Aes256GcmAlgorithm,
    Aes256GcmInput,
    Aes256GcmOutput,
    create_aes256gcm,
    create_aes256gcm_from_password,
)
from lib.util.kms.providers import LocalKeyProvider


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def algo(key: bytes) -> Aes256GcmAlgorithm:
    return create_aes256gcm(key)


class TestAes256GcmInputOutput:
    """Test the unified I/O types for AES-256-GCM."""

    def test_input_plaintext_property(self) -> None:
        inp = Aes256GcmInput(plaintext=b"hello")
        assert inp.plaintext == b"hello"
        assert inp.data == b"hello"  # inherited from EncryptionInput

    def test_input_associated_data(self) -> None:
        inp = Aes256GcmInput(plaintext=b"x", associated_data=b"aad")
        assert inp.associated_data == b"aad"

    def test_input_associated_data_defaults_none(self) -> None:
        inp = Aes256GcmInput(plaintext=b"x")
        assert inp.associated_data is None

    def test_output_ciphertext_property(self) -> None:
        out = Aes256GcmOutput(ciphertext=b"ct", nonce=b"\x00" * 12)
        assert out.ciphertext == b"ct"
        assert out.data == b"ct"  # inherited from EncryptionOutput

    def test_output_nonce(self) -> None:
        nonce = os.urandom(12)
        out = Aes256GcmOutput(ciphertext=b"ct", nonce=nonce)
        assert out.nonce == nonce

    def test_output_metrics_default_empty(self) -> None:
        out = Aes256GcmOutput(ciphertext=b"ct", nonce=b"\x00" * 12)
        assert out.metrics == {}

    def test_output_with_metrics(self) -> None:
        out = Aes256GcmOutput(
            ciphertext=b"ct",
            nonce=b"\x00" * 12,
            metrics={"elapsed_ms": 0.5},
        )
        assert out.metrics["elapsed_ms"] == 0.5


class TestAes256GcmAlgorithmEncrypt:
    def test_encrypt_returns_aes256gcm_output(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"hello")
        result = algo.encrypt(inp)
        assert isinstance(result, Aes256GcmOutput)

    def test_encrypt_ciphertext_differs_from_plaintext(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"secret data")
        result = algo.encrypt(inp)
        assert result.ciphertext != b"secret data"

    def test_encrypt_nonce_is_12_bytes(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"x")
        result = algo.encrypt(inp)
        assert len(result.nonce) == 12

    def test_encrypt_metrics(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"hello world")
        result = algo.encrypt(inp)
        assert result.metrics["algorithm"] == "AES-256-GCM"
        assert result.metrics["operation"] == "encrypt"
        assert result.metrics["plaintext_bytes"] == 11
        assert "ciphertext_bytes" in result.metrics
        assert "elapsed_ms" in result.metrics

    def test_encrypt_with_associated_data(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"msg", associated_data=b"header")
        result = algo.encrypt(inp)
        assert isinstance(result, Aes256GcmOutput)
        assert result.associated_data == b"header"

    def test_encrypt_rejects_wrong_payload_type(self, algo: Aes256GcmAlgorithm) -> None:
        from lib.EncryptionAlgorithm import EncryptionInput

        with pytest.raises(TypeError, match="Expected Aes256GcmInput"):
            algo.encrypt(EncryptionInput(data=b"wrong type"))

    def test_encrypt_unique_nonces(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"x")
        nonces = {algo.encrypt(inp).nonce for _ in range(20)}
        assert len(nonces) == 20  # all unique


class TestAes256GcmAlgorithmDecrypt:
    def test_decrypt_returns_encryption_output(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"hello")
        encrypted = algo.encrypt(inp)
        result = algo.decrypt(encrypted)
        assert isinstance(result, EncryptionOutput)

    def test_round_trip(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"round trip test")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.data == b"round trip test"

    def test_round_trip_with_associated_data(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"msg", associated_data=b"aad")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.data == b"msg"

    def test_decrypt_metrics(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"test")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.metrics["algorithm"] == "AES-256-GCM"
        assert decrypted.metrics["operation"] == "decrypt"
        assert "elapsed_ms" in decrypted.metrics

    def test_decrypt_rejects_wrong_payload_type(self, algo: Aes256GcmAlgorithm) -> None:
        with pytest.raises(TypeError, match="Expected Aes256GcmOutput"):
            algo.decrypt(EncryptionOutput(data=b"wrong type"))

    def test_tampered_ciphertext_raises(self, algo: Aes256GcmAlgorithm) -> None:
        inp = Aes256GcmInput(plaintext=b"authentic")
        encrypted = algo.encrypt(inp)
        tampered = Aes256GcmOutput(
            ciphertext=b"\xff" * len(encrypted.ciphertext),
            nonce=encrypted.nonce,
        )
        with pytest.raises(Exception):  # InvalidTag
            algo.decrypt(tampered)


class TestFactoryFunctions:
    def test_create_aes256gcm(self, key: bytes) -> None:
        algo = create_aes256gcm(key)
        inp = Aes256GcmInput(plaintext=b"factory test")
        result = algo.encrypt(inp)
        dec = algo.decrypt(result)
        assert dec.data == b"factory test"

    def test_create_aes256gcm_from_password(self) -> None:
        salt = os.urandom(16)
        algo = create_aes256gcm_from_password("password123", salt, iterations=10000)
        inp = Aes256GcmInput(plaintext=b"kdf test")
        result = algo.encrypt(inp)
        dec = algo.decrypt(result)
        assert dec.data == b"kdf test"

    def test_no_key_provider_raises(self) -> None:
        algo = Aes256GcmAlgorithm()
        inp = Aes256GcmInput(plaintext=b"no key")
        with pytest.raises(Exception):
            algo.encrypt(inp)
