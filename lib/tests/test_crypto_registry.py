"""Tests for CryptoRegistry."""
import os

import pytest

from lib.notebook.context import CryptoRegistry


@pytest.fixture
def registry() -> CryptoRegistry:
    return CryptoRegistry()


class TestKeyManagement:
    def test_set_and_get_key(self, registry: CryptoRegistry) -> None:
        key = os.urandom(32)
        registry.set_key("main", key)
        assert registry.get_key("main") == key

    def test_get_missing_key_returns_none(self, registry: CryptoRegistry) -> None:
        assert registry.get_key("missing") is None

    def test_require_key_raises_on_missing(self, registry: CryptoRegistry) -> None:
        with pytest.raises(KeyError, match="not registered"):
            registry.require_key("missing")

    def test_require_key_returns_existing(self, registry: CryptoRegistry) -> None:
        key = os.urandom(32)
        registry.set_key("k", key)
        assert registry.require_key("k") == key


class TestSaltManagement:
    def test_set_explicit_salt(self, registry: CryptoRegistry) -> None:
        salt = b"fixed_salt_value"
        result = registry.set_salt("s", salt=salt)
        assert result == salt
        assert registry.get_salt("s") == salt

    def test_auto_generate_salt(self, registry: CryptoRegistry) -> None:
        result = registry.set_salt("s", size=16)
        assert len(result) == 16

    def test_set_salt_idempotent(self, registry: CryptoRegistry) -> None:
        first = registry.set_salt("s", size=16)
        second = registry.set_salt("s", size=16)
        assert first == second  # does not regenerate

    def test_get_missing_salt_returns_none(self, registry: CryptoRegistry) -> None:
        assert registry.get_salt("missing") is None

    def test_require_salt_raises_on_missing(self, registry: CryptoRegistry) -> None:
        with pytest.raises(KeyError, match="not registered"):
            registry.require_salt("missing")


class TestNonceManagement:
    def test_set_explicit_nonce(self, registry: CryptoRegistry) -> None:
        nonce = os.urandom(12)
        result = registry.set_nonce("n", nonce=nonce)
        assert result == nonce

    def test_auto_generate_nonce(self, registry: CryptoRegistry) -> None:
        result = registry.set_nonce("n", size=12)
        assert len(result) == 12

    def test_set_nonce_overwrites(self, registry: CryptoRegistry) -> None:
        first = registry.set_nonce("n", size=12)
        second = registry.set_nonce("n", size=12)
        # Nonces should always be unique — overwrite is by design
        assert registry.get_nonce("n") == second

    def test_get_missing_nonce_returns_none(self, registry: CryptoRegistry) -> None:
        assert registry.get_nonce("missing") is None

    def test_require_nonce_raises_on_missing(self, registry: CryptoRegistry) -> None:
        with pytest.raises(KeyError, match="not registered"):
            registry.require_nonce("missing")


class TestKDFManagement:
    def test_derive_with_registered_kdf(self, registry: CryptoRegistry) -> None:
        def xor_kdf(key: bytes, salt: bytes) -> bytes:
            return bytes(a ^ b for a, b in zip(key, salt))

        registry.set_kdf("xor", xor_kdf)
        registry.set_salt("s", salt=b"\xff" * 4)

        derived = registry.derive("xor", key=b"\x00" * 4, salt_name="s")
        assert derived == b"\xff" * 4

    def test_derive_caches_result(self, registry: CryptoRegistry) -> None:
        registry.set_kdf("identity", lambda k, s: k)
        registry.set_salt("s", salt=b"\x00")

        registry.derive("identity", key=b"key", salt_name="s", cache_as="dk")
        assert registry.get_derived_key("dk") == b"key"

    def test_derive_missing_kdf_raises(self, registry: CryptoRegistry) -> None:
        with pytest.raises(KeyError, match="not registered"):
            registry.derive("nonexistent", key=b"k", salt_name="s")

    def test_derive_missing_salt_raises(self, registry: CryptoRegistry) -> None:
        registry.set_kdf("kdf", lambda k, s: k)
        with pytest.raises(KeyError, match="not registered"):
            registry.derive("kdf", key=b"k", salt_name="missing")


class TestEncapsulation:
    def test_encapsulate_and_cache(self, registry: CryptoRegistry) -> None:
        def fake_encaps(pk: bytes) -> tuple[bytes, bytes]:
            return (b"ciphertext", b"shared_secret")

        registry.set_encapsulator("kem", fake_encaps)
        ct, ss = registry.encapsulate("kem", public_key=b"pk", cache_as="ss1")
        assert ct == b"ciphertext"
        assert ss == b"shared_secret"
        assert registry.get_shared_secret("ss1") == b"shared_secret"

    def test_decapsulate_and_cache(self, registry: CryptoRegistry) -> None:
        def fake_decaps(sk: bytes, ct: bytes) -> bytes:
            return b"shared_secret"

        registry.set_decapsulator("kem", fake_decaps)
        ss = registry.decapsulate("kem", secret_key=b"sk", ciphertext=b"ct", cache_as="ss2")
        assert ss == b"shared_secret"
        assert registry.get_shared_secret("ss2") == b"shared_secret"

    def test_encapsulate_missing_raises(self, registry: CryptoRegistry) -> None:
        with pytest.raises(KeyError, match="not registered"):
            registry.encapsulate("missing", public_key=b"pk")

    def test_decapsulate_missing_raises(self, registry: CryptoRegistry) -> None:
        with pytest.raises(KeyError, match="not registered"):
            registry.decapsulate("missing", secret_key=b"sk", ciphertext=b"ct")


class TestGenericDataStorage:
    def test_set_and_get(self, registry: CryptoRegistry) -> None:
        registry.set("foo", 42)
        assert registry.get("foo") == 42

    def test_get_missing_returns_default(self, registry: CryptoRegistry) -> None:
        assert registry.get("missing") is None
        assert registry.get("missing", "fallback") == "fallback"
