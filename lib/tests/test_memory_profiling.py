"""Tests for memory profiling decorator and metrics."""
import os

import pytest

from lib.notebook.context import AlgorithmResult
from lib.notebook.decorators import (
    algorithm,
    with_key,
    with_metrics,
    with_memory_profiling,
)


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


class TestWithMemoryProfiling:
    def test_metrics_include_peak_memory(self, key: bytes) -> None:
        @algorithm("MemTest")
        @with_key(key)
        @with_memory_profiling()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = Algo().encrypt(b"x" * 1000)
        assert result.success
        assert "peak_memory_bytes" in result.metrics
        assert result.metrics["peak_memory_bytes"] >= 0
        assert "memory_delta_bytes" in result.metrics

    def test_memory_profiling_flag_in_metrics(self, key: bytes) -> None:
        @algorithm("MemFlag")
        @with_key(key)
        @with_memory_profiling()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.metrics.get("memory_profiling") is True

    def test_no_memory_metrics_without_decorator(self, key: bytes) -> None:
        @algorithm("NoMem")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert "peak_memory_bytes" not in result.metrics
        assert "memory_delta_bytes" not in result.metrics

    def test_decrypt_also_profiled(self, key: bytes) -> None:
        @algorithm("MemDecrypt")
        @with_key(key)
        @with_memory_profiling()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = Algo().decrypt(b"test")
        assert result.success
        assert "peak_memory_bytes" in result.metrics
        assert "memory_delta_bytes" in result.metrics

    def test_stacks_with_other_decorators(self, key: bytes) -> None:
        @algorithm("FullStack")
        @with_key(key)
        @with_metrics()
        @with_memory_profiling()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        result = Algo().encrypt(b"test")
        assert result.metrics.get("detailed") is True
        assert result.metrics.get("memory_profiling") is True
        assert "peak_memory_bytes" in result.metrics

    def test_config_profile_memory_flag(self, key: bytes) -> None:
        @algorithm("ConfigCheck")
        @with_key(key)
        @with_memory_profiling()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        algo = Algo()
        assert algo._config.profile_memory is True

    def test_config_profile_memory_false_by_default(self, key: bytes) -> None:
        @algorithm("NoProfile")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data

        algo = Algo()
        assert algo._config.profile_memory is False
