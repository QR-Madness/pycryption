# lib/notebook/utils.py
"""
Utility functions for notebook algorithm development.

Provides key generation, quick testing, and benchmarking helpers.
"""
from __future__ import annotations

import os
import statistics as _stats
from typing import Any, Dict, List, Optional


def generate_key(size: int = 32) -> bytes:
    """Generate a random key for testing."""
    return os.urandom(size)


def generate_salt(size: int = 16) -> bytes:
    """Generate a random salt for KDF."""
    return os.urandom(size)


def _compute_timing_stats(times: List[float]) -> Dict[str, float]:
    """Compute statistical summary for a list of timing measurements."""
    if not times:
        return {}
    sorted_times = sorted(times)
    n = len(sorted_times)
    result: Dict[str, float] = {
        "avg": round(sum(times) / n, 3),
        "min": round(sorted_times[0], 3),
        "max": round(sorted_times[-1], 3),
    }
    if n >= 2:
        result["stddev"] = round(_stats.stdev(times), 3)
    else:
        result["stddev"] = 0.0
    result["p50"] = round(sorted_times[int(n * 0.50)], 3)
    result["p95"] = round(sorted_times[min(int(n * 0.95), n - 1)], 3)
    result["p99"] = round(sorted_times[min(int(n * 0.99), n - 1)], 3)
    return result


def quick_test(algo_instance: Any, test_data: bytes = b"Hello, PyCryption!") -> None:
    """
    Quick round-trip test for notebook development.

    Encrypts, decrypts, and verifies the algorithm works correctly.
    Prints results to stdout for notebook visibility.
    """
    config = getattr(algo_instance, "_config", None)
    name = config.name if config else "Unknown"
    print(f"Testing: {name}")
    print(f"Input: {test_data!r}")
    print("-" * 40)

    # Encrypt
    enc_result = algo_instance.encrypt(test_data)
    print(f"Encrypt: {enc_result}")
    if not enc_result.success:
        print(f"  ERROR: {enc_result.error}")
        return

    # Decrypt
    dec_result = algo_instance.decrypt(enc_result.output)
    print(f"Decrypt: {dec_result}")
    if not dec_result.success:
        print(f"  ERROR: {dec_result.error}")
        return

    # Verify
    if dec_result.output == test_data:
        print("Round-trip successful!")
    else:
        print("Round-trip FAILED!")
        print(f"  Expected: {test_data!r}")
        print(f"  Got: {dec_result.output!r}")


def benchmark(
    algo_instance: Any,
    data_sizes: Optional[list[int]] = None,
    iterations: int = 10,
) -> Dict[str, Any]:
    """
    Benchmark an algorithm across various data sizes.

    Returns dict with algorithm name, iteration count, and
    per-size benchmark results including timing, throughput,
    statistical metrics, and optional memory profiling data.
    """
    if data_sizes is None:
        data_sizes = [100, 1000, 10000, 100000]

    config = getattr(algo_instance, "_config", None)
    name = config.name if config else "Unknown"

    results: Dict[str, Any] = {
        "algorithm": name,
        "iterations": iterations,
        "benchmarks": [],
    }

    for size in data_sizes:
        data = os.urandom(size)
        encrypt_times: list[float] = []
        decrypt_times: list[float] = []
        encrypt_memory: list[int] = []
        decrypt_memory: list[int] = []
        expansion_ratios: list[float] = []

        for _ in range(iterations):
            enc_result = algo_instance.encrypt(data)
            if enc_result.success:
                encrypt_times.append(enc_result.metrics.get("elapsed_ms", 0))
                if "peak_memory_bytes" in enc_result.metrics:
                    encrypt_memory.append(enc_result.metrics["peak_memory_bytes"])
                if "expansion_ratio" in enc_result.metrics:
                    expansion_ratios.append(enc_result.metrics["expansion_ratio"])

            dec_result = algo_instance.decrypt(enc_result.output)
            if dec_result.success:
                decrypt_times.append(dec_result.metrics.get("elapsed_ms", 0))
                if "peak_memory_bytes" in dec_result.metrics:
                    decrypt_memory.append(dec_result.metrics["peak_memory_bytes"])

        # Statistical timing
        enc_stats = _compute_timing_stats(encrypt_times)
        dec_stats = _compute_timing_stats(decrypt_times)

        avg_encrypt = enc_stats.get("avg", 0)
        avg_decrypt = dec_stats.get("avg", 0)

        throughput = 0.0
        if avg_encrypt > 0:
            throughput = round((size / 1_000_000) / (avg_encrypt / 1000), 2)

        # Operations per second (based on encrypt)
        ops_per_sec = 0.0
        if avg_encrypt > 0:
            ops_per_sec = round(1000.0 / avg_encrypt, 2)

        entry: Dict[str, Any] = {
            "size_bytes": size,
            # Backward-compatible keys
            "avg_encrypt_ms": avg_encrypt,
            "avg_decrypt_ms": avg_decrypt,
            "throughput_mbps": throughput,
            # Statistical keys
            "min_encrypt_ms": enc_stats.get("min", 0),
            "max_encrypt_ms": enc_stats.get("max", 0),
            "stddev_encrypt_ms": enc_stats.get("stddev", 0),
            "p50_encrypt_ms": enc_stats.get("p50", 0),
            "p95_encrypt_ms": enc_stats.get("p95", 0),
            "p99_encrypt_ms": enc_stats.get("p99", 0),
            "min_decrypt_ms": dec_stats.get("min", 0),
            "max_decrypt_ms": dec_stats.get("max", 0),
            "stddev_decrypt_ms": dec_stats.get("stddev", 0),
            "p50_decrypt_ms": dec_stats.get("p50", 0),
            "p95_decrypt_ms": dec_stats.get("p95", 0),
            "p99_decrypt_ms": dec_stats.get("p99", 0),
            "ops_per_sec": ops_per_sec,
        }

        # Optional memory metrics (only present when profiling enabled)
        if encrypt_memory:
            entry["avg_peak_encrypt_memory_bytes"] = round(
                sum(encrypt_memory) / len(encrypt_memory)
            )
            if size > 0:
                entry["memory_per_byte"] = round(
                    entry["avg_peak_encrypt_memory_bytes"] / size, 2
                )
        if decrypt_memory:
            entry["avg_peak_decrypt_memory_bytes"] = round(
                sum(decrypt_memory) / len(decrypt_memory)
            )
        if expansion_ratios:
            entry["avg_expansion_ratio"] = round(
                sum(expansion_ratios) / len(expansion_ratios), 4
            )

        results["benchmarks"].append(entry)

    # Scaling analysis (if multiple sizes)
    benchmarks = results["benchmarks"]
    if len(benchmarks) >= 2:
        first_tp = benchmarks[0].get("throughput_mbps", 0)
        last_tp = benchmarks[-1].get("throughput_mbps", 0)
        if first_tp > 0:
            results["scaling_factor"] = round(last_tp / first_tp, 3)
        else:
            results["scaling_factor"] = None

    return results
