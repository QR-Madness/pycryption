# lib/notebook/analysis.py
"""
Output quality analysis — the lab's instruments for judging ciphertext,
not just timing it.

These checks catch *cryptographically* broken prototypes that round-trip
and benchmark just fine:

- Shannon entropy: good ciphertext is indistinguishable from random
  (~8.0 bits/byte). Low entropy means structure is leaking.
- Chi-squared uniformity: byte frequencies should be uniform; skew that
  entropy misses shows up here.
- Avalanche effect: flipping one plaintext bit should change ~50% of
  ciphertext bits. Note: ciphers with random nonces/encapsulation pass
  trivially (two encryptions differ regardless) — the diagnostic value is
  in LOW scores, which expose deterministic, diffusion-free designs like
  repeating-key XOR.
- ECB canary: encrypting repetitive plaintext must not produce repeated
  ciphertext blocks; duplicates are the classic ECB-mode red flag.

All functions operate on raw bytes or notebook-API algorithm instances
(anything whose ``encrypt(data)`` returns an ``AlgorithmResult``).
"""
from __future__ import annotations

import math
import os
from collections import Counter
from typing import Any, Dict

# Critical values for chi-squared with 255 degrees of freedom.
# Testing against fixed critical values avoids a scipy dependency.
CHI2_CRITICAL_DOF255_A05 = 293.248   # reported as the "uniform" boolean
CHI2_CRITICAL_DOF255_A001 = 330.52   # used for flagging (0.1% false-positive)

AVALANCHE_HEALTHY_RANGE = (45.0, 55.0)


def min_expected_entropy(n: int) -> float:
    """
    Flagging threshold for the Shannon entropy of *n* random bytes.

    A finite random sample never measures exactly 8.0 bits/byte — the
    expected shortfall (Miller-Madow bias) is ~255/(2·n·ln 2). Allow four
    times that bias as margin so clean ciphers aren't flagged on small
    samples, capped near 8 for large ones.
    """
    if n <= 0:
        return 0.0
    bias = 255 / (2 * n * math.log(2))
    return min(7.97, 8.0 - 4 * bias)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def chi_squared_uniformity(data: bytes) -> Dict[str, Any]:
    """
    Chi-squared test of byte-value uniformity against the flat distribution.

    Returns the statistic, degrees of freedom, and whether it clears the
    alpha=0.05 critical value. Meaningful for samples >= ~1280 bytes
    (expected count >= 5 per byte value).
    """
    n = len(data)
    expected = n / 256
    counts = Counter(data)
    statistic = sum(
        (counts.get(b, 0) - expected) ** 2 / expected for b in range(256)
    )
    return {
        "statistic": round(statistic, 2),
        "dof": 255,
        "critical_value": CHI2_CRITICAL_DOF255_A05,
        "uniform": statistic <= CHI2_CRITICAL_DOF255_A05,
    }


def bit_difference_ratio(a: bytes, b: bytes) -> float:
    """Percentage of differing bits between two byte strings (over the shorter length)."""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    differing = sum((x ^ y).bit_count() for x, y in zip(a[:n], b[:n]))
    return differing / (n * 8) * 100


def avalanche_effect(algo: Any, sample_size: int = 1024, trials: int = 16) -> float:
    """
    Average % of ciphertext bits changed when one random plaintext bit flips.

    Each trial encrypts a baseline plaintext and a one-bit-flipped variant,
    then measures the bit difference between the two ciphertexts. ~50% is
    healthy; near-zero exposes diffusion-free designs (e.g., XOR streams).
    Randomized ciphers (fresh nonce per call) pass trivially — interpret
    low scores, not high ones.
    """
    rng = os.urandom
    total = 0.0
    for _ in range(trials):
        plaintext = bytearray(rng(sample_size))
        baseline = algo.encrypt(bytes(plaintext))
        if not baseline.success:
            raise RuntimeError(f"encrypt failed during avalanche test: {baseline.error}")

        bit = int.from_bytes(rng(4), "big") % (sample_size * 8)
        plaintext[bit // 8] ^= 1 << (bit % 8)
        flipped = algo.encrypt(bytes(plaintext))
        if not flipped.success:
            raise RuntimeError(f"encrypt failed during avalanche test: {flipped.error}")

        total += bit_difference_ratio(baseline.output, flipped.output)
    return round(total / trials, 2)


def ecb_canary(algo: Any, block_size: int = 16, blocks: int = 64) -> Dict[str, Any]:
    """
    Encrypt *blocks* identical plaintext blocks and count duplicated
    ciphertext blocks. Any duplication is an ECB-style structure leak.
    """
    plaintext = bytes(block_size) * blocks
    result = algo.encrypt(plaintext)
    if not result.success:
        raise RuntimeError(f"encrypt failed during ECB canary: {result.error}")

    ciphertext = result.output
    chunks = [
        ciphertext[i: i + block_size]
        for i in range(0, len(ciphertext) - block_size + 1, block_size)
    ]
    counts = Counter(chunks)
    duplicates = sum(c - 1 for c in counts.values() if c > 1)
    return {
        "blocks_scanned": len(chunks),
        "duplicate_blocks": duplicates,
        "clean": duplicates == 0,
    }


def analyze_output(algo: Any, sample_size: int = 4096, trials: int = 16) -> Dict[str, Any]:
    """
    Full output-quality panel for one notebook-API algorithm instance.

    Returns entropy, chi-squared uniformity, avalanche %, ECB canary, and a
    list of flags (empty list == healthy).
    """
    enc = algo.encrypt(os.urandom(sample_size))
    if not enc.success:
        return {"error": enc.error, "flags": ["encrypt-failed"]}

    ciphertext = enc.output
    entropy = round(shannon_entropy(ciphertext), 4)
    chi2 = chi_squared_uniformity(ciphertext)
    avalanche = avalanche_effect(algo, sample_size=min(sample_size, 1024), trials=trials)
    canary = ecb_canary(algo)

    flags = []
    if entropy < min_expected_entropy(len(ciphertext)):
        flags.append("low-entropy")
    if chi2["statistic"] > CHI2_CRITICAL_DOF255_A001:
        flags.append("non-uniform-bytes")
    if avalanche < AVALANCHE_HEALTHY_RANGE[0]:
        flags.append("weak-avalanche")
    if not canary["clean"]:
        flags.append("ecb-pattern")

    return {
        "entropy_bits_per_byte": entropy,
        "chi2_statistic": chi2["statistic"],
        "chi2_uniform": chi2["uniform"],
        "avalanche_pct": avalanche,
        "ecb_duplicate_blocks": canary["duplicate_blocks"],
        "flags": flags,
    }
