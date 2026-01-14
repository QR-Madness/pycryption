# lib/notebook/composer.py
"""
Composer session for algorithm management and benchmarking.

Provides a lightweight harness to register, test, and compare
multiple algorithms in notebook environments.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from lib.notebook.context import AlgorithmResult


@dataclass
class AlgorithmMetrics:
    """Aggregated metrics for a registered algorithm."""

    name: str
    encrypt_calls: int = 0
    decrypt_calls: int = 0
    total_encrypt_ms: float = 0.0
    total_decrypt_ms: float = 0.0
    total_bytes_processed: int = 0
    errors: int = 0

    @property
    def avg_encrypt_ms(self) -> float:
        if self.encrypt_calls > 0:
            return self.total_encrypt_ms / self.encrypt_calls
        return 0.0

    @property
    def avg_decrypt_ms(self) -> float:
        if self.decrypt_calls > 0:
            return self.total_decrypt_ms / self.decrypt_calls
        return 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "encrypt_calls": self.encrypt_calls,
            "decrypt_calls": self.decrypt_calls,
            "avg_encrypt_ms": round(self.avg_encrypt_ms, 3),
            "avg_decrypt_ms": round(self.avg_decrypt_ms, 3),
            "total_bytes_processed": self.total_bytes_processed,
            "errors": self.errors,
        }


class ComposerSession:
    """
    Algorithm manager and benchmarker for notebook-style algorithms.

    Register prototype algorithms alongside proven implementations from
    lib/algorithms to compare performance and validate behavior.
    """

    def __init__(self) -> None:
        self._algorithms: Dict[str, Any] = {}
        self._metrics: Dict[str, AlgorithmMetrics] = {}

    def register(self, algo_instance: Any, name: Optional[str] = None) -> "ComposerSession":
        """
        Register an algorithm instance for management.

        Args:
            algo_instance: A decorated algorithm instance
            name: Optional override name (defaults to algorithm's configured name)

        Returns:
            self for chaining
        """
        config = getattr(algo_instance, "_config", None)
        algo_name = name or (config.name if config else algo_instance.__class__.__name__)

        self._algorithms[algo_name] = algo_instance
        self._metrics[algo_name] = AlgorithmMetrics(name=algo_name)
        return self

    def list_algorithms(self) -> list[str]:
        """List all registered algorithm names."""
        return list(self._algorithms.keys())

    def get(self, name: str) -> Any:
        """Get a registered algorithm by name."""
        if name not in self._algorithms:
            raise KeyError(f"Algorithm '{name}' not registered")
        return self._algorithms[name]

    def encrypt(self, name: str, data: bytes) -> AlgorithmResult:
        """Encrypt data using the named algorithm."""
        algo = self.get(name)
        metrics = self._metrics[name]

        result = algo.encrypt(data)
        metrics.encrypt_calls += 1

        if result.success:
            metrics.total_encrypt_ms += result.metrics.get("elapsed_ms", 0)
            metrics.total_bytes_processed += len(data)
        else:
            metrics.errors += 1

        return result

    def decrypt(self, name: str, data: bytes) -> AlgorithmResult:
        """Decrypt data using the named algorithm."""
        algo = self.get(name)
        metrics = self._metrics[name]

        result = algo.decrypt(data)
        metrics.decrypt_calls += 1

        if result.success:
            metrics.total_decrypt_ms += result.metrics.get("elapsed_ms", 0)
            metrics.total_bytes_processed += len(data)
        else:
            metrics.errors += 1

        return result

    def test(self, name: str, test_data: bytes = b"Hello, PyCryption!") -> bool:
        """
        Run a round-trip test on the named algorithm.

        Returns True if encryption followed by decryption
        produces the original data.
        """
        enc_result = self.encrypt(name, test_data)
        if not enc_result.success:
            return False

        dec_result = self.decrypt(name, enc_result.output)
        if not dec_result.success:
            return False

        return dec_result.output == test_data

    def test_all(self, test_data: bytes = b"Hello, PyCryption!") -> Dict[str, bool]:
        """Run round-trip tests on all registered algorithms."""
        return {name: self.test(name, test_data) for name in self._algorithms}

    def benchmark(
        self,
        name: str,
        data_sizes: Optional[list[int]] = None,
        iterations: int = 10,
    ) -> Dict[str, Any]:
        """Benchmark a specific algorithm across data sizes."""
        from lib.notebook.utils import benchmark as run_benchmark

        algo = self.get(name)
        return run_benchmark(algo, data_sizes=data_sizes, iterations=iterations)

    def benchmark_all(
        self,
        data_sizes: Optional[list[int]] = None,
        iterations: int = 10,
    ) -> Dict[str, Dict[str, Any]]:
        """Benchmark all registered algorithms."""
        return {
            name: self.benchmark(name, data_sizes=data_sizes, iterations=iterations)
            for name in self._algorithms
        }

    def compare(
        self,
        data_size: int = 10000,
        iterations: int = 50,
    ) -> list[Dict[str, Any]]:
        """
        Compare all registered algorithms at a specific data size.

        Returns sorted list of performance results (fastest first).
        """
        results = []

        for name in self._algorithms:
            bench = self.benchmark(name, data_sizes=[data_size], iterations=iterations)
            if bench["benchmarks"]:
                entry = bench["benchmarks"][0]
                results.append({
                    "algorithm": name,
                    "avg_encrypt_ms": entry["avg_encrypt_ms"],
                    "avg_decrypt_ms": entry["avg_decrypt_ms"],
                    "throughput_mbps": entry["throughput_mbps"],
                })

        results.sort(key=lambda x: x["avg_encrypt_ms"])
        return results

    def report(self) -> Dict[str, Dict[str, Any]]:
        """Get aggregated metrics for all algorithms."""
        return {name: m.as_dict() for name, m in self._metrics.items()}

    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        for name in self._metrics:
            self._metrics[name] = AlgorithmMetrics(name=name)
