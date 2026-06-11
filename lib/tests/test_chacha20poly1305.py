"""Direct tests for ChaCha20Poly1305Algorithm (not through the adapter/notebook layer)."""
import os

import pytest

from lib.EncryptionAlgorithm import EncryptionOutput
from lib.algorithms import (
    ChaCha20Poly1305Algorithm,
    ChaCha20Poly1305Input,
    ChaCha20Poly1305Output,
    create_chacha20poly1305,
    create_chacha20poly1305_from_password,
)


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def algo(key: bytes) -> ChaCha20Poly1305Algorithm:
    return create_chacha20poly1305(key)


class TestChaCha20Poly1305InputOutput:
    """Test the unified I/O types for ChaCha20-Poly1305."""

    def test_input_plaintext_property(self) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"hello")
        assert inp.plaintext == b"hello"
        assert inp.data == b"hello"  # inherited from EncryptionInput

    def test_input_associated_data(self) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"x", associated_data=b"aad")
        assert inp.associated_data == b"aad"

    def test_input_associated_data_defaults_none(self) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"x")
        assert inp.associated_data is None

    def test_output_ciphertext_property(self) -> None:
        out = ChaCha20Poly1305Output(ciphertext=b"ct", nonce=b"\x00" * 12)
        assert out.ciphertext == b"ct"
        assert out.data == b"ct"  # inherited from EncryptionOutput

    def test_output_nonce(self) -> None:
        nonce = os.urandom(12)
        out = ChaCha20Poly1305Output(ciphertext=b"ct", nonce=nonce)
        assert out.nonce == nonce

    def test_output_metrics_default_empty(self) -> None:
        out = ChaCha20Poly1305Output(ciphertext=b"ct", nonce=b"\x00" * 12)
        assert out.metrics == {}


class TestChaCha20Poly1305Encrypt:
    def test_encrypt_returns_chacha_output(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"hello")
        result = algo.encrypt(inp)
        assert isinstance(result, ChaCha20Poly1305Output)

    def test_encrypt_ciphertext_differs_from_plaintext(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"secret data")
        result = algo.encrypt(inp)
        assert result.ciphertext != b"secret data"

    def test_encrypt_nonce_is_12_bytes(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"x")
        result = algo.encrypt(inp)
        assert len(result.nonce) == 12

    def test_encrypt_metrics(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"hello world")
        result = algo.encrypt(inp)
        assert result.metrics["algorithm"] == "ChaCha20-Poly1305"
        assert result.metrics["operation"] == "encrypt"
        assert result.metrics["plaintext_bytes"] == 11
        assert "ciphertext_bytes" in result.metrics
        assert "elapsed_ms" in result.metrics

    def test_encrypt_with_associated_data(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"msg", associated_data=b"header")
        result = algo.encrypt(inp)
        assert isinstance(result, ChaCha20Poly1305Output)
        assert result.associated_data == b"header"

    def test_encrypt_rejects_wrong_payload_type(self, algo: ChaCha20Poly1305Algorithm) -> None:
        from lib.EncryptionAlgorithm import EncryptionInput

        with pytest.raises(TypeError, match="Expected ChaCha20Poly1305Input"):
            algo.encrypt(EncryptionInput(data=b"wrong type"))

    def test_encrypt_unique_nonces(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"x")
        nonces = {algo.encrypt(inp).nonce for _ in range(20)}
        assert len(nonces) == 20  # all unique


class TestChaCha20Poly1305Decrypt:
    def test_decrypt_returns_encryption_output(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"hello")
        encrypted = algo.encrypt(inp)
        result = algo.decrypt(encrypted)
        assert isinstance(result, EncryptionOutput)

    def test_round_trip(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"round trip test")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.data == b"round trip test"

    def test_round_trip_with_associated_data(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"msg", associated_data=b"aad")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.data == b"msg"

    def test_decrypt_metrics(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"test")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.metrics["algorithm"] == "ChaCha20-Poly1305"
        assert decrypted.metrics["operation"] == "decrypt"
        assert "elapsed_ms" in decrypted.metrics

    def test_decrypt_rejects_wrong_payload_type(self, algo: ChaCha20Poly1305Algorithm) -> None:
        with pytest.raises(TypeError, match="Expected ChaCha20Poly1305Output"):
            algo.decrypt(EncryptionOutput(data=b"wrong type"))

    def test_tampered_ciphertext_raises(self, algo: ChaCha20Poly1305Algorithm) -> None:
        inp = ChaCha20Poly1305Input(plaintext=b"authentic")
        encrypted = algo.encrypt(inp)
        tampered = ChaCha20Poly1305Output(
            ciphertext=b"\xff" * len(encrypted.ciphertext),
            nonce=encrypted.nonce,
        )
        with pytest.raises(Exception):  # InvalidTag
            algo.decrypt(tampered)


class TestFactoryFunctions:
    def test_create_chacha20poly1305(self, key: bytes) -> None:
        algo = create_chacha20poly1305(key)
        inp = ChaCha20Poly1305Input(plaintext=b"factory test")
        result = algo.encrypt(inp)
        dec = algo.decrypt(result)
        assert dec.data == b"factory test"

    def test_create_chacha20poly1305_from_password(self) -> None:
        salt = os.urandom(16)
        algo = create_chacha20poly1305_from_password("password123", salt, iterations=10000)
        inp = ChaCha20Poly1305Input(plaintext=b"kdf test")
        result = algo.encrypt(inp)
        dec = algo.decrypt(result)
        assert dec.data == b"kdf test"

    def test_no_key_provider_raises(self) -> None:
        algo = ChaCha20Poly1305Algorithm()
        inp = ChaCha20Poly1305Input(plaintext=b"no key")
        with pytest.raises(Exception):
            algo.encrypt(inp)
