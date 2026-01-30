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

# Report builder
from lib.notebook.report import ReportBuilder

# Adapters for lib/algorithms
from lib.notebook.adapters import (
    wrap_aes256gcm,
)

# Re-export key providers for convenience
from lib.util.kms.providers import (
    KeyProvider,
    LocalKeyProvider,
    EnvKeyProvider,
    DerivedKeyProvider,
    KmsKeyProvider,
    KeyProviderError,
)

# Re-export composer types
from lib.EncryptionAlgorithm import (
    SIMPLE_COMPOSER_TYPE,
    MULTI_COMPOSER_TYPE,
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
    # Composer
    "ComposerSession",
    "AlgorithmMetrics",
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
    # Report builder
    "ReportBuilder",
    # Adapters
    "wrap_aes256gcm",
    # Constants
    "SIMPLE_COMPOSER_TYPE",
    "MULTI_COMPOSER_TYPE",
]
