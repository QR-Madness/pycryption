# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyCryption is an **encryption research repository** for demonstrating algorithms, production mechanisms, and prototype designs while collecting benchmarks. The goal is to reduce cognitive overhead when testing implementable encryption patterns, prototype algorithms, and KDF designs.

The core abstraction is **encryption composers** — specialized harnesses that wrap encryption algorithms with automatic metrics collection. Supports both traditional cryptography (`cryptography` library) and post-quantum cryptography (`pqcrypto`).

## Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) package manager

## Commands

```bash
# Install dependencies
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

## Testing Philosophy

Tests ensure all components work and are traceable in failures. Given the sensitive nature of cryptographic research, test coverage is critical for validating correctness and catching regressions in algorithm implementations.

## Architecture

### Core Components

- **`lib/EncryptionAlgorithm.py`**: Base class and Input/Output types for all algorithms. Defines `SIMPLE_COMPOSER_TYPE` and `MULTI_COMPOSER_TYPE` constants.
- **`lib/algorithms/`**: Production-ready algorithm implementations (e.g., `Aes256GcmAlgorithm`)
- **`lib/notebook/`**: Declarative API for rapid prototyping in Jupyter notebooks
- **`lib/util/kms/`**: Key management via KeyProvider pattern

### Two Pathways for Algorithm Creation

**Option 1: Notebook API (recommended for prototyping)**

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
- `LocalKeyProvider` — In-memory key (testing/development)
- `EnvKeyProvider` — Key from environment variable (containers/CI)
- `DerivedKeyProvider` — KDF from password (PBKDF2 with 480k iterations, scrypt)
- `KmsKeyProvider` — External KMS integration (extend for AWS/GCP/Azure)

**Method Decorator:** Use `@inject_key(key_length=32)` on encrypt/decrypt to auto-inject keys.

### Notebook API (`lib/notebook/`)

Declarative API for rapid algorithm prototyping in Jupyter notebooks.

**Class decorators** handle logistics (key injection, context, metrics):
- `@algorithm(name)` — Base decorator, wraps class with context injection and `AlgorithmResult` return types
- `@with_key(key)` — Inject raw key bytes or a `KeyProvider` instance
- `@with_password(password, salt)` — Derive key from password via `DerivedKeyProvider`
- `@with_env_key(env_var)` — Load key from environment variable
- `@with_metrics()` — Enable detailed metrics collection (timestamps, detailed flag)
- `@with_memory_profiling()` — Enable memory profiling via `tracemalloc` (opt-in, adds overhead)

**AlgorithmContext (`ctx`)** injected into encrypt/decrypt:
- `ctx.key` — Key bytes from provider
- `ctx.metrics` — Dict for collecting metrics
- `ctx.elapsed_ms()` — Timing helper
- `ctx.registry` — Access the `CryptoRegistry` for all cryptographic materials
- `ctx.derive(kdf_name, salt_name)` — Derive key using registered KDF and salt
- `ctx.set_nonce(name)` / `ctx.get_nonce(name)` — Nonce management via registry
- `ctx.set_salt(name)` / `ctx.get_salt(name)` — Salt management via registry

**CryptoRegistry** (`context.py`) is the single source of truth for all cryptographic materials. It persists across encrypt/decrypt calls on an instance and stores: keys, salts, nonces, derived keys, shared secrets, KDF functions, and encapsulation/decapsulation functions (for PQ/KEM algorithms like Kyber).

**ComposerSession** (`composer.py`) for benchmarking prototypes against production algorithms:
- `register()` — Register algorithm instances
- `test_all()` — Round-trip verification
- `benchmark_all()` — Performance benchmarks
- `compare()` — Side-by-side comparison (sorted by speed)

**ReportBuilder** (`report.py`) generates styled output for Jupyter notebooks using `rich` tables, HTML, or plain text via `tabulate`.

**Adapters** (`adapters.py`) bridge `lib/algorithms` to the notebook API via the generic `adapt()` factory:
```python
from lib.notebook import adapt
from lib.algorithms import Aes256GcmAlgorithm

algo = adapt(Aes256GcmAlgorithm, key, name="AES-256-GCM", profile_memory=True)
```
`adapt()` accepts `profile_memory` and `collect_metrics` flags to enable the full decorator stack on production algorithms.

**Utilities** (`utils.py`): `generate_key()`, `generate_salt()`, `quick_test()`, `benchmark()`

## Security

Run Snyk security scans on new first-party code. Fix any issues found, rescan, and repeat until clean before committing.
