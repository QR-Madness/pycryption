# PyCryption Roadmap

## Simple Composer - Operational Baseline

### Algorithm Implementation
- [x] Implement a concrete symmetric algorithm (e.g., AES-256-GCM) extending `EncryptionAlgorithm`
- [x] Implement ChaCha20-Poly1305 (RFC 8439) as a second production AEAD
- [x] Implement ML-KEM-768 + AES-256-GCM hybrid (post-quantum KEM-DEM, FIPS 203)
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

## Multi Encryption - Baseline

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

## Comprehensive Algorithm Analysis — NEXT UP (output QA suite)

### CPU Measurement
- [ ] Add `cpu_time_ms` via `time.process_time()` — actual CPU work excluding sleep/IO
- [ ] Add CPU efficiency ratio (`cpu_time / wall_time`) — indicates CPU-bound vs IO-bound

### Output Quality Analysis
- [ ] Shannon entropy of ciphertext (bits/byte, ideal ~8.0 for good ciphers)
- [ ] Byte frequency distribution with chi-squared uniformity test
- [ ] Avalanche effect — flip 1 bit in plaintext, measure % of ciphertext bits changed (ideal ~50%)
- [ ] Key sensitivity — flip 1 bit in key, measure % of ciphertext bits changed (ideal ~50%)
- [ ] Pattern detection — repeated ciphertext blocks, autocorrelation (ECB mode red flag)

### Throughput
- [ ] Add MB/sec throughput metric alongside ops/sec (standard in OpenSSL/libsodium benchmarks)

### Timing Consistency
- [ ] Coefficient of variation (stddev/mean) — flags potential timing side-channels
- [ ] Timing variance by input content — constant-time implementations should show low CV regardless of data


## Lab Office (Site)

Goal: serve the notebooks as a crisp, low-maintenance site, with room for
rich notebooks, exercises, and a cryptography on-ramp mathematics track.

### Stack Decision
- [ ] Pin the stack — **Quarto recommended**: renders committed `.ipynb`
      outputs without re-executing (friendliest to our outputs-in-git
      convention), single binary + one `_quarto.yml`, native KaTeX for the
      math track, ANSI-aware output rendering for `rich` tables
- [ ] Runner-up: MyST/Jupyter Book 2 (exercise/proof directives are strong
      for course content) — revisit if Quarto theming disappoints
- [ ] Next.js/Vite assessment: notebooks become second-class (own the
      ipynb→MDX pipeline, ANSI, math, highlighting); only worth it if the
      site becomes a product. Keep notebooks canonical so migration stays
      possible later.

### Candidate A — Root Project (start here)
- [ ] `_quarto.yml` at repo root; notebooks stay where they are, listed as
      render targets — zero import breakage, minimal churn
- [ ] Index page: lab overview + latest specimen comparison
- [ ] Theme pass: dark/light, output styling; use ReportBuilder HTML mode
      where rich-table ANSI renders poorly

### Candidate B — Lab Wings (graduate when on-ramp content lands)
- [ ] Reorganize content into `specimens/`, `composer/`, `on-ramp/`,
      `exercises/` directories with section navigation
- [ ] Fix `from lib...` imports for relocated notebooks (execute from repo
      root — `exec_notebooks.py` already pins kernel cwd to root)

### On-Ramp Mathematics
- [ ] Outline curriculum: modular arithmetic → groups/rings/fields →
      discrete log & factoring → elliptic curves → lattices (LWE → ML-KEM)
- [ ] Exercise format: callouts with collapsible solutions; evaluate
      quarto-live (Pyodide) for in-browser exercises
- [ ] First chapter: modular arithmetic, tied into the XOR/Caesar specimens

### Publishing
- [ ] GitHub Actions: `task nb:check` smoke test on push
- [ ] Render + publish site to GitHub Pages on master

---

## Lab Ops

- [x] `Taskfile.yml` front desk: `task test`, `task ride`, `task ride:full`,
      `task nb:exec`, `task nb:check`, `task site:*` (quarto-gated), `task clean`
- [x] `scripts/ride.py` — specimen benchmarks from the terminal, no IDE needed
- [x] `scripts/exec_notebooks.py` — headless notebook execution (in-place or --check)
- [ ] Wire `task bench:save` once benchmark persistence lands (JSON keyed by
      commit/machine)

---

## Utilities

- [ ] Expand `DataGenerator` with binary data generation (not just ASCII)
- [ ] Add deterministic seeded generation for reproducible benchmarks
