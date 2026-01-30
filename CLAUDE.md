# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyCryption is an **encryption research repository** for demonstrating algorithms, production mechanisms, and prototype designs while collecting benchmarks. The goal is to reduce cognitive overhead when testing implementable encryption patterns, prototype algorithms, and KDF designs.

The core abstraction is **encryption composers** - specialized harnesses that wrap encryption algorithms with automatic metrics collection. Supports both traditional cryptography (`cryptography` library) and post-quantum cryptography (`pqcrypto`).

## Testing Philosophy

Tests ensure all components work and are traceable in failures. Given the sensitive nature of cryptographic research, test coverage is critical for validating correctness and catching regressions in algorithm implementations.

## Commands

```bash
# Install dependencies (uses uv package manager)
uv sync

# Run all tests
python -m pytest lib/tests/

# Run a single test file
python -m pytest lib/tests/test_file.py

# Run a specific test
python -m pytest lib/tests/test_file.py::TestClass::test_method

# Run Jupyter notebooks
jupyter notebook
```

## Architecture

### Core Components

- **`lib/EncryptionAlgorithm.py`**: Base class and Input/Output types for all algorithms
- **`lib/algorithms/`**: Production-ready algorithm implementations (e.g., `Aes256GcmAlgorithm`)
- **`lib/notebook/`**: Declarative API for rapid prototyping in Jupyter notebooks
- **`lib/util/kms/`**: Key management via KeyProvider pattern

### Creating New Algorithms

**Option 1: Using the Notebook API (recommended for prototyping)**

```python
from lib.notebook import algorithm, with_key, generate_key

@algorithm("MyAlgorithm")
@with_key(generate_key(32))
class MyAlgorithm:
    def encrypt(self, data: bytes, ctx) -> bytes:
        # ctx.key contains the injected key
        return encrypted_data

    def decrypt(self, data: bytes, ctx) -> bytes:
        return decrypted_data
```

**Option 2: Subclassing EncryptionAlgorithm (production implementations)**

1. Subclass `EncryptionAlgorithm` from `lib/EncryptionAlgorithm.py`
2. Set composer type: `super().__init__(composer_type=SIMPLE_COMPOSER_TYPE)`
3. Implement `encrypt()` and `decrypt()` methods
4. Use `SimpleEncryptionAlgorithmInput`/`Output` or `MultiEncryptionAlgorithmInput`/`Output`
5. Configure key management via KeyProvider

### Key Providers (`lib/util/kms/`)

Key management is decoupled from algorithms via the KeyProvider pattern:

```python
from lib.util.kms.providers import LocalKeyProvider, use_key_provider
from lib.algorithms import Aes256GcmAlgorithm, create_aes256gcm

# Option 1: Class decorator
@use_key_provider(LocalKeyProvider(my_key))
class MyAlgorithm(Aes256GcmAlgorithm):
    pass

# Option 2: Runtime configuration
algo = Aes256GcmAlgorithm()
algo._key_provider = LocalKeyProvider(my_key)

# Option 3: Factory functions
algo = create_aes256gcm(key)
algo = create_aes256gcm_from_password(password, salt)
```

**Available Providers:**
- `LocalKeyProvider` - In-memory key (testing/development)
- `EnvKeyProvider` - Key from environment variable (containers/CI)
- `DerivedKeyProvider` - KDF from password (PBKDF2, scrypt)
- `KmsKeyProvider` - External KMS integration (extend for AWS/GCP/Azure)

**Method Decorator:** Use `@inject_key(key_length=32)` on encrypt/decrypt to auto-inject keys.

### Notebook API (`lib/notebook/`)

Declarative API for rapid algorithm prototyping in Jupyter notebooks:

- `context.py` - AlgorithmConfig, AlgorithmContext, AlgorithmResult, ContextRegistry
- `decorators.py` - @algorithm, @with_key, @with_kdf, @with_salt, etc.
- `composer.py` - ComposerSession, AlgorithmMetrics
- `utils.py` - generate_key, generate_salt, quick_test, benchmark
- `adapters.py` - Bridges lib/algorithms to notebook API (e.g., `wrap_aes256gcm`)

**Decorators** handle logistics (key injection, context, metrics):
- `@algorithm(name)` - Base decorator, wraps class with context injection
- `@with_key(key)` - Inject raw key or KeyProvider
- `@with_password(password, salt)` - Derive key from password
- `@with_env_key(env_var)` - Load key from environment variable
- `@with_kdf(name, func)` - Register a named KDF function
- `@with_salt(name, salt)` - Register a named salt (auto-generates if not provided)
- `@with_metrics()` - Enable detailed metrics collection

**AlgorithmContext (`ctx`)** injected into encrypt/decrypt:
- `ctx.key` - Key bytes from provider
- `ctx.nonce` - Auto-generated nonce
- `ctx.metrics` - Dict for collecting metrics
- `ctx.elapsed_ms()` - Timing helper
- `ctx.registry` - Access to named KDFs, salts, and layer materials
- `ctx.derive(kdf_name, salt_name)` - Derive key using registered KDF and salt
- `ctx.layer(name)` - Access named layer materials for multi-layer encryption

**ComposerSession** for benchmarking prototypes against lib/algorithms:
- `register()` - Register algorithm instances
- `test_all()` - Round-trip verification
- `benchmark_all()` - Performance benchmarks
- `compare()` - Side-by-side comparison (sorted by speed)

### Notebooks

Interactive experimentation via Jupyter notebooks:
- `Symmetric.ipynb` - Symmetric encryption benchmarks
- `Asymmetric.ipynb` - Asymmetric encryption examples
- `KYBER.ipynb` - Post-quantum key encapsulation
- `Encryption Composer.ipynb` - Composer usage examples
- `General Cryptography.ipynb` - General cryptographic concepts

## Security

Run Snyk security scans on new code. Fix any issues found before committing.
