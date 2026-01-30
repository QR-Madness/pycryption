"""Tests for KeyProvider implementations."""
import os
import base64

import pytest

from lib.util.kms.providers import (
    KeyProvider,
    LocalKeyProvider,
    EnvKeyProvider,
    DerivedKeyProvider,
    KmsKeyProvider,
    KeyNotFoundError,
    KeyValidationError,
    KeyProviderError,
)


class TestLocalKeyProvider:
    def test_returns_key(self) -> None:
        key = os.urandom(32)
        provider = LocalKeyProvider(key)
        assert provider.get_key() == key

    def test_ignores_key_id(self) -> None:
        key = os.urandom(32)
        provider = LocalKeyProvider(key)
        assert provider.get_key("anything") == key

    def test_validate_key_correct_length(self) -> None:
        key = os.urandom(32)
        provider = LocalKeyProvider(key)
        provider.validate_key(key, 32)  # should not raise

    def test_validate_key_wrong_length(self) -> None:
        key = os.urandom(16)
        provider = LocalKeyProvider(key)
        with pytest.raises(KeyValidationError, match="Expected 32-byte key"):
            provider.validate_key(key, 32)


class TestEnvKeyProvider:
    def test_reads_base64_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = os.urandom(32)
        encoded = base64.b64encode(key).decode()
        monkeypatch.setenv("TEST_KEY", encoded)

        provider = EnvKeyProvider("TEST_KEY")
        assert provider.get_key() == key

    def test_falls_back_to_raw_encoding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A value that is NOT valid base64
        monkeypatch.setenv("TEST_KEY", "not-base64!!!")

        provider = EnvKeyProvider("TEST_KEY")
        result = provider.get_key()
        assert result == b"not-base64!!!"

    def test_missing_env_var_raises(self) -> None:
        provider = EnvKeyProvider("NONEXISTENT_VAR_12345")
        with pytest.raises(KeyNotFoundError, match="not set"):
            provider.get_key()


class TestDerivedKeyProvider:
    def test_pbkdf2_derives_key(self) -> None:
        salt = os.urandom(16)
        provider = DerivedKeyProvider(
            password="test",
            salt=salt,
            key_length=32,
            kdf="pbkdf2",
            iterations=10000,
        )
        key = provider.get_key()
        assert len(key) == 32

    def test_pbkdf2_deterministic(self) -> None:
        salt = os.urandom(16)
        p1 = DerivedKeyProvider(password="test", salt=salt, kdf="pbkdf2", iterations=10000)
        p2 = DerivedKeyProvider(password="test", salt=salt, kdf="pbkdf2", iterations=10000)
        assert p1.get_key() == p2.get_key()

    def test_pbkdf2_different_passwords_differ(self) -> None:
        salt = os.urandom(16)
        p1 = DerivedKeyProvider(password="alpha", salt=salt, kdf="pbkdf2", iterations=10000)
        p2 = DerivedKeyProvider(password="beta", salt=salt, kdf="pbkdf2", iterations=10000)
        assert p1.get_key() != p2.get_key()

    def test_scrypt_derives_key(self) -> None:
        salt = os.urandom(16)
        provider = DerivedKeyProvider(
            password="test",
            salt=salt,
            key_length=32,
            kdf="scrypt",
        )
        key = provider.get_key()
        assert len(key) == 32

    def test_caches_derived_key(self) -> None:
        salt = os.urandom(16)
        provider = DerivedKeyProvider(
            password="test",
            salt=salt,
            kdf="pbkdf2",
            iterations=10000,
        )
        first = provider.get_key()
        second = provider.get_key()
        assert first is second  # same object, not re-derived

    def test_unsupported_kdf_raises(self) -> None:
        salt = os.urandom(16)
        provider = DerivedKeyProvider(
            password="test",
            salt=salt,
            kdf="argon2",
        )
        with pytest.raises(KeyProviderError, match="Unsupported KDF"):
            provider.get_key()


class TestKmsKeyProvider:
    def test_fetch_not_implemented(self) -> None:
        provider = KmsKeyProvider(
            client_factory=lambda: None,
            key_id="test-key",
        )
        with pytest.raises(NotImplementedError):
            provider.get_key()

    def test_subclass_can_implement(self) -> None:
        class StubKms(KmsKeyProvider):
            def _fetch_from_kms(self, key_id: str) -> bytes:
                return b"k" * 32

        provider = StubKms(client_factory=lambda: "client", key_id="id")
        assert provider.get_key() == b"k" * 32

    def test_caches_key(self) -> None:
        call_count = 0

        class CountingKms(KmsKeyProvider):
            def _fetch_from_kms(self, key_id: str) -> bytes:
                nonlocal call_count
                call_count += 1
                return b"k" * 32

        provider = CountingKms(
            client_factory=lambda: "client",
            key_id="id",
            cache_ttl_seconds=300,
        )
        provider.get_key()
        provider.get_key()
        assert call_count == 1
