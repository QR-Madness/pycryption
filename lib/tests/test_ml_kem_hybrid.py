"""Direct tests for MlKem768HybridAlgorithm (not through the adapter/notebook layer)."""
import pytest

from lib.EncryptionAlgorithm import EncryptionInput, EncryptionOutput
from lib.algorithms import (
    MlKem768HybridAlgorithm,
    MlKem768HybridInput,
    MlKem768HybridOutput,
    create_ml_kem_768_hybrid,
)


@pytest.fixture
def algo() -> MlKem768HybridAlgorithm:
    return create_ml_kem_768_hybrid()


class TestMlKem768HybridInputOutput:
    """Test the unified I/O types for the ML-KEM-768 hybrid."""

    def test_input_plaintext_property(self) -> None:
        inp = MlKem768HybridInput(plaintext=b"hello")
        assert inp.plaintext == b"hello"
        assert inp.data == b"hello"  # inherited from EncryptionInput

    def test_input_associated_data_defaults_none(self) -> None:
        inp = MlKem768HybridInput(plaintext=b"x")
        assert inp.associated_data is None

    def test_output_carries_kem_ciphertext_and_nonce(self) -> None:
        out = MlKem768HybridOutput(
            ciphertext=b"ct",
            kem_ciphertext=b"\x00" * 1088,
            nonce=b"\x00" * 12,
        )
        assert out.ciphertext == b"ct"
        assert out.data == b"ct"
        assert len(out.kem_ciphertext) == 1088
        assert len(out.nonce) == 12


class TestKeypairManagement:
    def test_no_arg_constructor_generates_keypair(self) -> None:
        algo = MlKem768HybridAlgorithm()
        assert len(algo.public_key) == MlKem768HybridAlgorithm.PUBLIC_KEY_SIZE
        assert len(algo.secret_key) == MlKem768HybridAlgorithm.SECRET_KEY_SIZE

    def test_generate_keypair_sizes(self) -> None:
        pk, sk = MlKem768HybridAlgorithm.generate_keypair()
        assert len(pk) == 1184
        assert len(sk) == 2400

    def test_encrypt_only_instance(self) -> None:
        pk, _ = MlKem768HybridAlgorithm.generate_keypair()
        algo = MlKem768HybridAlgorithm(public_key=pk)
        result = algo.encrypt(MlKem768HybridInput(plaintext=b"to recipient"))
        assert isinstance(result, MlKem768HybridOutput)

    def test_encrypt_only_instance_cannot_decrypt(self) -> None:
        pk, _ = MlKem768HybridAlgorithm.generate_keypair()
        algo = MlKem768HybridAlgorithm(public_key=pk)
        encrypted = algo.encrypt(MlKem768HybridInput(plaintext=b"x"))
        with pytest.raises(ValueError, match="No secret key"):
            algo.decrypt(encrypted)

    def test_recipient_with_keypair_decrypts_sender_message(self) -> None:
        pk, sk = MlKem768HybridAlgorithm.generate_keypair()
        sender = MlKem768HybridAlgorithm(public_key=pk)
        recipient = MlKem768HybridAlgorithm(public_key=pk, secret_key=sk)
        encrypted = sender.encrypt(MlKem768HybridInput(plaintext=b"pq message"))
        decrypted = recipient.decrypt(encrypted)
        assert decrypted.data == b"pq message"


class TestMlKem768HybridEncrypt:
    def test_encrypt_returns_hybrid_output(self, algo: MlKem768HybridAlgorithm) -> None:
        result = algo.encrypt(MlKem768HybridInput(plaintext=b"hello"))
        assert isinstance(result, MlKem768HybridOutput)

    def test_encrypt_ciphertext_differs_from_plaintext(self, algo: MlKem768HybridAlgorithm) -> None:
        result = algo.encrypt(MlKem768HybridInput(plaintext=b"secret data"))
        assert result.ciphertext != b"secret data"

    def test_kem_ciphertext_size(self, algo: MlKem768HybridAlgorithm) -> None:
        result = algo.encrypt(MlKem768HybridInput(plaintext=b"x"))
        assert len(result.kem_ciphertext) == MlKem768HybridAlgorithm.KEM_CIPHERTEXT_SIZE

    def test_encrypt_metrics(self, algo: MlKem768HybridAlgorithm) -> None:
        result = algo.encrypt(MlKem768HybridInput(plaintext=b"hello world"))
        assert result.metrics["algorithm"] == "ML-KEM-768+AES-256-GCM"
        assert result.metrics["operation"] == "encrypt"
        assert result.metrics["plaintext_bytes"] == 11
        assert result.metrics["kem_ciphertext_bytes"] == 1088
        assert "kem_elapsed_ms" in result.metrics
        assert "elapsed_ms" in result.metrics

    def test_encrypt_rejects_wrong_payload_type(self, algo: MlKem768HybridAlgorithm) -> None:
        with pytest.raises(TypeError, match="Expected MlKem768HybridInput"):
            algo.encrypt(EncryptionInput(data=b"wrong type"))

    def test_each_encrypt_uses_fresh_encapsulation(self, algo: MlKem768HybridAlgorithm) -> None:
        inp = MlKem768HybridInput(plaintext=b"x")
        kem_cts = {algo.encrypt(inp).kem_ciphertext for _ in range(5)}
        assert len(kem_cts) == 5  # fresh shared secret per message


class TestMlKem768HybridDecrypt:
    def test_round_trip(self, algo: MlKem768HybridAlgorithm) -> None:
        encrypted = algo.encrypt(MlKem768HybridInput(plaintext=b"round trip test"))
        decrypted = algo.decrypt(encrypted)
        assert decrypted.data == b"round trip test"

    def test_round_trip_with_associated_data(self, algo: MlKem768HybridAlgorithm) -> None:
        inp = MlKem768HybridInput(plaintext=b"msg", associated_data=b"aad")
        encrypted = algo.encrypt(inp)
        decrypted = algo.decrypt(encrypted)
        assert decrypted.data == b"msg"

    def test_decrypt_metrics(self, algo: MlKem768HybridAlgorithm) -> None:
        encrypted = algo.encrypt(MlKem768HybridInput(plaintext=b"test"))
        decrypted = algo.decrypt(encrypted)
        assert decrypted.metrics["algorithm"] == "ML-KEM-768+AES-256-GCM"
        assert decrypted.metrics["operation"] == "decrypt"
        assert "kem_elapsed_ms" in decrypted.metrics

    def test_decrypt_rejects_wrong_payload_type(self, algo: MlKem768HybridAlgorithm) -> None:
        with pytest.raises(TypeError, match="Expected MlKem768HybridOutput"):
            algo.decrypt(EncryptionOutput(data=b"wrong type"))

    def test_tampered_ciphertext_raises(self, algo: MlKem768HybridAlgorithm) -> None:
        encrypted = algo.encrypt(MlKem768HybridInput(plaintext=b"authentic"))
        tampered = MlKem768HybridOutput(
            ciphertext=b"\xff" * len(encrypted.ciphertext),
            kem_ciphertext=encrypted.kem_ciphertext,
            nonce=encrypted.nonce,
        )
        with pytest.raises(Exception):  # InvalidTag
            algo.decrypt(tampered)

    def test_wrong_recipient_cannot_decrypt(self, algo: MlKem768HybridAlgorithm) -> None:
        encrypted = algo.encrypt(MlKem768HybridInput(plaintext=b"for someone else"))
        other = MlKem768HybridAlgorithm()  # different keypair
        # ML-KEM decapsulation with the wrong key yields a different (implicit
        # rejection) secret, so GCM authentication must fail.
        with pytest.raises(Exception):  # InvalidTag
            other.decrypt(encrypted)


class TestNotebookAdapter:
    def test_adapt_without_key(self) -> None:
        from lib.notebook import adapt

        nb_algo = adapt(MlKem768HybridAlgorithm, name="ML-KEM-768-Hybrid")
        enc = nb_algo.encrypt(b"adapter ride")
        assert enc.success, enc.error
        dec = nb_algo.decrypt(enc.output)
        assert dec.success, dec.error
        assert dec.output == b"adapter ride"
