"""Tests for extended benchmark statistical metrics."""
import os

import pytest

from lib.notebook.decorators import algorithm, with_key, with_memory_profiling
from lib.notebook.utils import benchmark, _compute_timing_stats


class TestComputeTimingStats:
    def test_basic_stats(self) -> None:
        times = [1.0, 2.0, 3.0, 4.0, 5.0]
        stats = _compute_timing_stats(times)
        assert stats["avg"] == 3.0
        assert stats["min"] == 1.0
        assert stats["max"] == 5.0
        assert "stddev" in stats
        assert stats["stddev"] > 0
        assert "p50" in stats
        assert "p95" in stats
        assert "p99" in stats

    def test_empty_list(self) -> None:
        assert _compute_timing_stats([]) == {}

    def test_single_element(self) -> None:
        stats = _compute_timing_stats([5.0])
        assert stats["avg"] == 5.0
        assert stats["min"] == 5.0
        assert stats["max"] == 5.0
        assert stats["stddev"] == 0.0
        assert stats["p50"] == 5.0

    def test_two_elements(self) -> None:
        stats = _compute_timing_stats([1.0, 3.0])
        assert stats["avg"] == 2.0
        assert stats["min"] == 1.0
        assert stats["max"] == 3.0
        assert stats["stddev"] > 0

    def test_percentiles_ordering(self) -> None:
        times = list(range(1, 101))  # 1 to 100
        times_float = [float(t) for t in times]
        stats = _compute_timing_stats(times_float)
        assert stats["p50"] <= stats["p95"]
        assert stats["p95"] <= stats["p99"]


class TestBenchmarkStatistics:
    def test_benchmark_includes_statistical_keys(self) -> None:
        key = os.urandom(32)

        @algorithm("StatAlgo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[100], iterations=5)
        entry = result["benchmarks"][0]
        assert "min_encrypt_ms" in entry
        assert "max_encrypt_ms" in entry
        assert "stddev_encrypt_ms" in entry
        assert "p50_encrypt_ms" in entry
        assert "p95_encrypt_ms" in entry
        assert "p99_encrypt_ms" in entry
        assert "min_decrypt_ms" in entry
        assert "max_decrypt_ms" in entry
        assert "stddev_decrypt_ms" in entry
        assert "p50_decrypt_ms" in entry
        assert "p95_decrypt_ms" in entry
        assert "p99_decrypt_ms" in entry
        assert "ops_per_sec" in entry

    def test_ops_per_sec_positive(self) -> None:
        key = os.urandom(32)

        @algorithm("OpsAlgo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[100], iterations=3)
        entry = result["benchmarks"][0]
        assert entry["ops_per_sec"] > 0

    def test_scaling_factor_present(self) -> None:
        key = os.urandom(32)

        @algorithm("ScaleAlgo")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[100, 10000], iterations=3)
        assert "scaling_factor" in result

    def test_no_scaling_factor_single_size(self) -> None:
        key = os.urandom(32)

        @algorithm("SingleSize")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[100], iterations=3)
        assert "scaling_factor" not in result

    def test_memory_metrics_in_benchmark(self) -> None:
        key = os.urandom(32)

        @algorithm("MemBench")
        @with_key(key)
        @with_memory_profiling()
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[1000], iterations=3)
        entry = result["benchmarks"][0]
        assert "avg_peak_encrypt_memory_bytes" in entry
        assert "memory_per_byte" in entry
        assert "avg_peak_decrypt_memory_bytes" in entry

    def test_no_memory_metrics_without_profiling(self) -> None:
        key = os.urandom(32)

        @algorithm("NoMemBench")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[100], iterations=3)
        entry = result["benchmarks"][0]
        assert "avg_peak_encrypt_memory_bytes" not in entry
        assert "memory_per_byte" not in entry

    def test_expansion_ratio_in_benchmark(self) -> None:
        key = os.urandom(32)

        @algorithm("Expander")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data + b"tag1234567890123"  # 16-byte auth tag

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[:-16]

        result = benchmark(Algo(), data_sizes=[100], iterations=3)
        entry = result["benchmarks"][0]
        assert "avg_expansion_ratio" in entry
        assert entry["avg_expansion_ratio"] > 1.0

    def test_backward_compatible_keys_still_present(self) -> None:
        key = os.urandom(32)

        @algorithm("BackCompat")
        @with_key(key)
        class Algo:
            def encrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

            def decrypt(self, data: bytes, ctx) -> bytes:
                return data[::-1]

        result = benchmark(Algo(), data_sizes=[100], iterations=3)
        entry = result["benchmarks"][0]
        # These must always be present for backward compat
        assert "size_bytes" in entry
        assert "avg_encrypt_ms" in entry
        assert "avg_decrypt_ms" in entry
        assert "throughput_mbps" in entry
