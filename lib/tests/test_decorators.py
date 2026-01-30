"""Tests for notebook decorators (@algorithm, @with_key, etc.)."""
import os
import time

import pytest

from lib.notebook.context import AlgorithmResult
from lib.notebook.decorators import (
    algorithm,
    with_key,
    with_password,
    with_env_key,
    with_metrics,
)
from lib.util.kms.providers import LocalKeyProvider


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


class TestAlgorithmDecorator:
    def test_wraps_encrypt_returns_algorithm_result(self, key: bytes) -> None:
        @algorithm("TestAlgo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = Algo().encrypt(b"hello")
        assert isinstance(result, AlgorithmResult)
        assert result.success is True
        assert result.output == b"olleh"

    def test_wraps_decrypt_returns_algorithm_result(self, key: bytes) -> None:
        @algorithm("TestAlgo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = Algo().decrypt(b"hello")
        assert isinstance(result, AlgorithmResult)
        assert result.output == b"olleh"

    def test_metrics_include_algorithm_name(self, key: bytes) -> None:
        @algorithm("MyName")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.metrics["algorithm"] == "MyName"

    def test_metrics_include_operation(self, key: bytes) -> None:
        @algorithm("Algo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        enc = Algo().encrypt(b"x")
        assert enc.metrics["operation"] == "encrypt"

        dec = Algo().decrypt(b"x")
        assert dec.metrics["operation"] == "decrypt"

    def test_metrics_include_byte_counts(self, key: bytes) -> None:
        @algorithm("Algo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data + b"extra"

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"hello")
        assert result.metrics["input_bytes"] == 5
        assert result.metrics["output_bytes"] == 10

    def test_error_captured_in_result(self, key: bytes) -> None:
        @algorithm("Failing")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                raise ValueError("boom")

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.success is False
        assert "boom" in result.error

    def test_separate_instances_have_isolated_config(self, key: bytes) -> None:
        @algorithm("Algo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        a = Algo()
        b = Algo()
        a._config.name = "Modified"
        assert b._config.name == "Algo"


class TestExpansionRatio:
    def test_expansion_ratio_in_encrypt_metrics(self, key: bytes) -> None:
        @algorithm("Expander")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data + b"tag123"  # simulates auth tag

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[:-6]

        result = Algo().encrypt(b"hello")
        assert "expansion_ratio" in result.metrics
        assert result.metrics["expansion_ratio"] == round(11 / 5, 4)

    def test_no_expansion_ratio_in_decrypt(self, key: bytes) -> None:
        @algorithm("NoExpand")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().decrypt(b"hello")
        assert "expansion_ratio" not in result.metrics

    def test_expansion_ratio_one_for_no_overhead(self, key: bytes) -> None:
        @algorithm("NoOverhead")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data  # same size

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"hello")
        assert result.metrics["expansion_ratio"] == 1.0

    def test_no_expansion_ratio_for_empty_input(self, key: bytes) -> None:
        @algorithm("EmptyInput")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return b"something"

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"")
        assert "expansion_ratio" not in result.metrics


class TestWithKey:
    def test_injects_raw_bytes(self) -> None:
        key = os.urandom(32)

        @algorithm("Algo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                assert len(ctx.key) == 32
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.success is True

    def test_injects_key_provider(self) -> None:
        key = os.urandom(32)
        provider = LocalKeyProvider(key)

        @algorithm("Algo")
        @with_key(provider)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                assert ctx.key == key
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.success is True


class TestWithPassword:
    def test_derives_key_from_password(self) -> None:
        salt = os.urandom(16)

        @algorithm("Algo")
        @with_password("secret", salt, iterations=10000)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                assert len(ctx.key) == 32
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.success is True


class TestWithEnvKey:
    def test_loads_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import base64

        key = os.urandom(32)
        monkeypatch.setenv("TEST_ALGO_KEY", base64.b64encode(key).decode())

        @algorithm("Algo")
        @with_env_key("TEST_ALGO_KEY")
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                assert ctx.key == key
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.success is True


class TestWithMetrics:
    def test_adds_detailed_flag(self) -> None:
        key = os.urandom(32)

        @algorithm("Algo")
        @with_key(key)
        @with_metrics()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.metrics.get("detailed") is True
        assert "timestamp" in result.metrics


class TestDecoratorStacking:
    def test_full_stack(self) -> None:
        key = os.urandom(32)

        @algorithm("FullStack")
        @with_key(key)
        @with_metrics()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        algo = Algo()
        enc = algo.encrypt(b"hello")
        assert enc.success
        assert enc.metrics["algorithm"] == "FullStack"
        assert enc.metrics["detailed"] is True

        dec = algo.decrypt(enc.output)
        assert dec.success
        assert dec.output == b"hello"

    def test_registry_persists_across_calls(self) -> None:
        key = os.urandom(32)

        @algorithm("Stateful")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                ctx.set("saved", "from_encrypt")
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                assert ctx.get("saved") == "from_encrypt"
                return data

        algo = Algo()
        algo.encrypt(b"test")
        result = algo.decrypt(b"test")
        assert result.success is True
