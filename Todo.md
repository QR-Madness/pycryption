# PyCryption Roadmap

## Simple Composer - Operational Baseline

### Algorithm Implementation
- [x] Implement a concrete symmetric algorithm (e.g., AES-256-GCM) extending `EncryptionAlgorithm`
- [ ] Implement a concrete asymmetric algorithm (e.g., RSA or ECDH) for key exchange demos

### Input/Output Classes
- [x] Expand `SimpleEncryptionAlgorithmInput` with required fields: plaintext bytes, optional metadata
- [x] Expand `SimpleEncryptionAlgorithmOutput` with required fields: ciphertext bytes, nonce/IV, auth tag (for AEAD)

### Key Management
- [x] Implement KeyProvider pattern for decoupled key handling (`lib/util/key_providers.py`)
- [x] Add key derivation support (PBKDF2, scrypt via `DerivedKeyProvider`)
- [x] Define key storage/reference pattern via provider classes
- [x] Create `@use_key_provider` class decorator for algorithm configuration
- [x] Create `@inject_key` method decorator for automatic key injection
- [ ] Implement concrete `KmsKeyProvider` for AWS/GCP/Azure
- [ ] Add Argon2 support to `DerivedKeyProvider`
- [ ] Add HKDF support for key expansion

### Metrics & Reporting
- [x] Basic timing metrics in algorithm output
- [x] Add throughput metrics (ops/sec) and statistical timing (min/max/stddev/p50/p95/p99)
- [x] Add memory usage tracking via `@with_memory_profiling()` decorator (opt-in, tracemalloc-based)
- [x] Add expansion ratio metrics for encrypt operations
- [x] Add scaling analysis across data sizes in `benchmark()`
- [x] Create structured report export (`ReportBuilder` with rich/HTML/text output)

---

## Multi Composer - Baseline

### Core Implementation
- [ ] Implement `encrypt()` method to chain data through all layers sequentially
- [ ] Implement `decrypt()` method (reverse layer order)
- [ ] Handle intermediate data format between layers

### Key Propagation
- [ ] Design key propagation strategy (shared key, per-layer keys, derived keys)
- [ ] Implement key injection per layer (leverage KeyProvider pattern)

### Layer Management
- [ ] Add layer ordering/priority support
- [ ] Add ability to remove/reorder layers after construction
- [ ] Consider layer enable/disable toggling for A/B testing

### Metrics
- [ ] Add per-layer timing metrics
- [ ] Add aggregate metrics across all layers
- [ ] Create layered report structure showing each algorithm's contribution

### Input/Output Types
- [ ] Define `MultiEncryptionAlgorithmInput` fields
- [ ] Define `MultiEncryptionAlgorithmOutput` fields with layer metadata

---

## Notebook API (`lib/notebook/`)

- [x] Create declarative `@algorithm` decorator with context injection
- [x] Create `@with_key`, `@with_password`, `@with_env_key` decorators
- [x] Create `@with_aead` decorator for AESGCM primitive injection
- [x] Create `AlgorithmContext` dataclass for injected state
- [x] Create `AlgorithmResult` wrapper with metrics
- [x] Add `quick_test()` and `benchmark()` utilities
- [x] Add `@with_chacha20` decorator for ChaCha20-Poly1305
- [x] Add `ComposerSession` class for algorithm management & benchmarking
- [x] Add `@with_metrics()` decorator for detailed metrics (timestamps)
- [x] Add `@with_memory_profiling()` decorator for memory tracking
- [x] Add `CryptoRegistry` for persistent cryptographic material storage
- [x] Add `ReportBuilder` for styled Jupyter output (rich/HTML/text)
- [x] Add `adapt()` factory to bridge production algorithms to notebook API
- [ ] Add layer context fields for multi-composer integration
- [ ] Add `@with_compression` decorator for pre-encrypt compression
- [ ] Add visualization helpers for benchmark results (matplotlib/pandas)

---

## Utilities

- [ ] Expand `DataGenerator` with binary data generation (not just ASCII)
- [ ] Add deterministic seeded generation for reproducible benchmarks
