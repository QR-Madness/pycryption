#!/usr/bin/env python
"""
Terminal ride for the specimen shelf — no IDE or Jupyter required.

Registers every production algorithm in a ComposerSession, verifies
round-trips, and prints comparison + scaling tables via ReportBuilder.

Usage:
    python scripts/ride.py
    python scripts/ride.py --size 100000 --iterations 100
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.algorithms import (
    Aes256GcmAlgorithm,
    ChaCha20Poly1305Algorithm,
    MlKem768HybridAlgorithm,
)
from lib.notebook import ComposerSession, ReportBuilder, adapt


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the specimen shelf.")
    parser.add_argument("--size", type=int, default=10_000, help="payload bytes for comparison")
    parser.add_argument("--iterations", type=int, default=50, help="iterations for comparison")
    parser.add_argument(
        "--scaling",
        action="store_true",
        help="also run the scaling analysis (100 B - 100 KB)",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="also run the output quality panel (entropy, avalanche, ECB canary)",
    )
    parser.add_argument(
        "--save",
        nargs="?",
        const="",
        default=None,
        metavar="LABEL",
        help="persist a seeded benchmark run to benchmarks/ (optional label)",
    )
    parser.add_argument(
        "--seed",
        default="pycryption",
        help="payload seed for saved runs (default: pycryption)",
    )
    args = parser.parse_args()

    key = os.urandom(32)
    report = ReportBuilder()
    session = ComposerSession()

    session.register(adapt(Aes256GcmAlgorithm, key, name="AES-256-GCM", profile_memory=True))
    session.register(
        adapt(ChaCha20Poly1305Algorithm, key, name="ChaCha20-Poly1305", profile_memory=True)
    )
    session.register(
        adapt(MlKem768HybridAlgorithm, name="ML-KEM-768+AES-GCM", profile_memory=True)
    )

    report.heading("Round-trip Tests", level=2)
    results = session.test_all()
    report.test_results(results)
    if not all(results.values()):
        return 1

    report.heading(f"Comparison ({args.size:,} B, {args.iterations} iterations)", level=2)
    report.comparison_table(session.compare(data_size=args.size, iterations=args.iterations))

    if args.scaling:
        report.heading("Scaling Analysis", level=2)
        report.benchmark_table(
            session.benchmark_all(data_sizes=[100, 1_000, 10_000, 100_000], iterations=20)
        )

    if args.analyze:
        report.heading("Output Quality Analysis", level=2)
        report.analysis_table(session.analyze_all())

    if args.save is not None:
        from lib.notebook import save_benchmark_run

        report.heading("Persisting Benchmark Run", level=2)
        benchmarks = session.benchmark_all(
            data_sizes=[100, 1_000, 10_000, 100_000],
            iterations=args.iterations,
            seed=args.seed,
        )
        path = save_benchmark_run(
            benchmarks,
            label=args.save or None,
            seed=args.seed,
            iterations=args.iterations,
            analysis=session.analyze_all(),
        )
        report.success(f"Saved {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
