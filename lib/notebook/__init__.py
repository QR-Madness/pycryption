# lib/notebook/__init__.py
"""
Notebook-friendly API for encryption algorithm development.

Provides decorators for logistics, a composer session for benchmarking,
and utilities for rapid prototyping in Jupyter notebooks.

Usage:
    from lib.notebook import *

Modules:
    context     - AlgorithmConfig, AlgorithmContext, AlgorithmResult
    decorators  - @algorithm, @with_key, @with_aead, etc.
    composer    - ComposerSession, AlgorithmMetrics
    utils       - generate_key, quick_test, benchmark
"""

# Context types
from lib.notebook.context import (
    AlgorithmConfig,
    AlgorithmContext,
    AlgorithmResult,
)

# Decorators
from lib.notebook.decorators import (
    algorithm,
    with_key,
    with_password,
    with_env_key,
    with_aead,
    with_chacha20,
    with_metrics,
    aes256gcm_algorithm,
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

# Adapters for lib/algorithms
from lib.notebook.adapters import (
    wrap_aes256gcm,
)

# Re-export key providers for convenience
from lib.util.key_providers import (
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
    # Decorators
    "algorithm",
    "with_key",
    "with_password",
    "with_env_key",
    "with_aead",
    "with_chacha20",
    "with_metrics",
    "aes256gcm_algorithm",
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
    # Adapters
    "wrap_aes256gcm",
    # Constants
    "SIMPLE_COMPOSER_TYPE",
    "MULTI_COMPOSER_TYPE",
]
