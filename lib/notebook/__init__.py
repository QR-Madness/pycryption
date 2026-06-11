# lib/notebook/__init__.py
"""
Notebook-friendly API for encryption algorithm development.

Provides decorators for logistics, a composer session for benchmarking,
and utilities for rapid prototyping in Jupyter notebooks.

Usage:
    from lib.notebook import *
"""

# Context types
from lib.notebook.context import (
    AlgorithmConfig,
    AlgorithmContext,
    AlgorithmResult,
    CryptoRegistry,
)

# Decorators
from lib.notebook.decorators import (
    algorithm,
    with_key,
    with_password,
    with_env_key,
    with_metrics,
    with_memory_profiling,
)

# Composer
from lib.notebook.composer import (
    ComposerSession,
    AlgorithmMetrics,
)

# Utilities
from lib.notebook.utils import (
    generate_key,
    generate_salt,
    quick_test,
    benchmark,
)

# Output quality analysis
from lib.notebook.analysis import (
    analyze_output,
    avalanche_effect,
    bit_difference_ratio,
    chi_squared_uniformity,
    ecb_canary,
    shannon_entropy,
)

# Multi Encryption pipeline
from lib.notebook.pipeline import MultiEncryption

# Benchmark persistence
from lib.notebook.persistence import (
    compare_runs,
    latest_run,
    load_runs,
    save_benchmark_run,
)

# Report builder
from lib.notebook.report import ReportBuilder

# Adapters for lib/algorithms
from lib.notebook.adapters import adapt

# Re-export key providers for convenience
from lib.util.kms.providers import (
    KeyProvider,
    LocalKeyProvider,
    EnvKeyProvider,
    DerivedKeyProvider,
    KmsKeyProvider,
    KeyProviderError,
)

__all__ = [
    # Context types
    "AlgorithmConfig",
    "AlgorithmContext",
    "AlgorithmResult",
    "CryptoRegistry",
    # Decorators
    "algorithm",
    "with_key",
    "with_password",
    "with_env_key",
    "with_metrics",
    "with_memory_profiling",
    # Composer
    "ComposerSession",
    "AlgorithmMetrics",
    # Multi Encryption pipeline
    "MultiEncryption",
    # Key providers
    "KeyProvider",
    "LocalKeyProvider",
    "EnvKeyProvider",
    "DerivedKeyProvider",
    "KmsKeyProvider",
    "KeyProviderError",
    # Utilities
    "generate_key",
    "generate_salt",
    "quick_test",
    "benchmark",
    # Output quality analysis
    "analyze_output",
    "avalanche_effect",
    "bit_difference_ratio",
    "chi_squared_uniformity",
    "ecb_canary",
    "shannon_entropy",
    # Benchmark persistence
    "compare_runs",
    "latest_run",
    "load_runs",
    "save_benchmark_run",
    # Report builder
    "ReportBuilder",
    # Adapters
    "adapt",
]
