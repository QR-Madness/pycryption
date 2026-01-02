# lib/notebook/utils.py
"""
Utility functions for notebook algorithm development.

Provides key generation, quick testing, and benchmarking helpers.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional


def generate_key(size: int = 32) -> bytes:
    """Generate a random key for testing."""
    return os.urandom(size)


def generate_salt(size: int = 16) -> bytes:
    """Generate a random salt for KDF."""
    return os.urandom(size)


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
    dec_result = algo_instance.decrypt(enc_result.output, nonce=enc_result.nonce)
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
    per-size benchmark results including timing and throughput.
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
        encrypt_times = []
        decrypt_times = []

        for _ in range(iterations):
            enc_result = algo_instance.encrypt(data)
            if enc_result.success:
                encrypt_times.append(enc_result.metrics.get("elapsed_ms", 0))

            dec_result = algo_instance.decrypt(enc_result.output, nonce=enc_result.nonce)
            if dec_result.success:
                decrypt_times.append(dec_result.metrics.get("elapsed_ms", 0))

        avg_encrypt = sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0
        avg_decrypt = sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0

        throughput = 0.0
        if avg_encrypt > 0:
            throughput = round((size / 1_000_000) / (avg_encrypt / 1000), 2)

        results["benchmarks"].append({
            "size_bytes": size,
            "avg_encrypt_ms": round(avg_encrypt, 3),
            "avg_decrypt_ms": round(avg_decrypt, 3),
            "throughput_mbps": throughput,
        })

    return results
