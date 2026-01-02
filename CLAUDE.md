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
python -m pytest lib/tests/test_simple_composer.py

# Run a specific test
python -m pytest lib/tests/test_simple_composer.py::TestSimpleComposer::test_composer_initialization

# Run Jupyter notebooks
jupyter notebook
```

## Architecture

### Composers

Composers are algorithm harnesses that manage encryption lifecycle and metrics. Two types exist:

- **SimpleEncryptionComposer** (`lib/SimpleEncryptionComposer.py`): Production-ready. Wraps a single algorithm with "fire and forget" semantics - you bootstrap an algorithm, call encrypt/decrypt, and get metrics automatically.

- **MultiEncryptionComposer** (`lib/prototype/`): Experimental. Supports layering multiple encryption algorithms sequentially. Uses `MultiEncryptionComposerLayer` for per-layer state and `EncryptionComposerLayerIterator` for traversal.

### Creating New Algorithms

1. Subclass `EncryptionAlgorithm` from `lib/EncryptionAlgorithm.py`
2. Set composer type in `__init__`: `super().__init__(composer_type=SIMPLE_COMPOSER_TYPE)` or `MULTI_COMPOSER_TYPE`
3. Implement `encrypt()` and `decrypt()` methods
4. Use corresponding Input/Output classes: `SimpleEncryptionAlgorithmInput`/`Output` or `MultiEncryptionAlgorithmInput`/`Output`
5. Configure key management via KeyProvider (see below)

### Key Providers (`lib/util/key_providers.py`)

Key management is decoupled from algorithms via the KeyProvider pattern:

```python
from lib.util.key_providers import LocalKeyProvider, use_key_provider
from lib.algorithms import Aes256GcmAlgorithm

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
- `KmsKeyProvider` - External KMS integration (stub, extend for AWS/GCP/Azure)

**Method Decorator:** Use `@inject_key(key_length=32)` on encrypt/decrypt to auto-inject keys.

### Notebook API (`lib/notebook.py`)

Declarative API for rapid algorithm prototyping in Jupyter notebooks:

```python
from lib.notebook import *

# Define algorithm with decorators
@algorithm("My-AES-Experiment")
@with_key(generate_key(32))
@with_aead()
class MyAlgorithm:
    def encrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        return ctx.aesgcm.encrypt(ctx.nonce, data, None)

    def decrypt(self, data: bytes, ctx: AlgorithmContext) -> bytes:
        return ctx.aesgcm.decrypt(ctx.nonce, data, None)

# Test immediately
quick_test(MyAlgorithm())
benchmark(MyAlgorithm())
```

**Available Decorators:**
- `@algorithm(name)` - Base decorator, wraps class with context injection
- `@with_key(key)` - Inject raw key or KeyProvider
- `@with_password(password, salt)` - Derive key from password
- `@with_aead()` - Pre-configure AESGCM primitive in context
- `@with_metrics()` - Enable detailed metrics collection
- `@aes256gcm_algorithm()` - All-in-one for AES-256-GCM

**Context Object (`ctx`):** Injected into encrypt/decrypt with:
- `ctx.key` - Key bytes
- `ctx.nonce` - Auto-generated nonce
- `ctx.aesgcm` - AESGCM instance (if using `@with_aead`)
- `ctx.metrics` - Dict for collecting metrics
- `ctx.elapsed_ms()` - Timing helper

### Notebooks

Interactive experimentation via Jupyter notebooks:
- `Symmetric.ipynb` - Symmetric encryption benchmarks
- `Asymmetric.ipynb` - Asymmetric encryption examples
- `KYBER.ipynb` - Post-quantum key encapsulation
- `Encryption Composer.ipynb` - Composer usage examples

## Security

Run Snyk security scans on new code. Fix any issues found before committing.
