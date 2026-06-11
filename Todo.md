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

## Multi Encryption - Baseline (`lib/notebook/pipeline.py`)

### Core Implementation
- [x] `MultiEncryption.encrypt()` chains data through enabled layers in order
- [x] `decrypt()` unwinds in reverse layer order
- [x] Intermediate format: raw bytes between layers; each layer keeps its own
      auxiliary state (nonces, KEM ciphertexts) in its instance registry
- [x] Pipelines quack like notebook-API algorithms — registerable in
      ComposerSession for benchmarks and output quality analysis

### Key Propagation
- [x] Per-layer keys: each layer manages its own KeyProvider/keypair
- [ ] Derived-key propagation (single master secret, per-layer HKDF) —
      revisit alongside the HKDF KeyProvider task

### Layer Management
- [x] Ordered layers with `move_layer(name, position)`
- [x] `add_layer` / `remove_layer` after construction
- [x] `enable()` / `disable()` toggling for A/B testing

### Metrics
- [x] Per-layer timing, byte counts, expansion ratios
- [x] Aggregate elapsed/expansion across the pipeline
- [x] `ReportBuilder.layers_table()` — each layer's contribution + time share

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

## Comprehensive Algorithm Analysis

### CPU Measurement
- [ ] Add `cpu_time_ms` via `time.process_time()` — actual CPU work excluding sleep/IO
- [ ] Add CPU efficiency ratio (`cpu_time / wall_time`) — indicates CPU-bound vs IO-bound

### Output Quality Analysis (`lib/notebook/analysis.py`)
- [x] Shannon entropy of ciphertext, with sample-size-aware flagging
      threshold (`min_expected_entropy` — Miller-Madow bias × 4 margin)
- [x] Byte frequency chi-squared uniformity test (no scipy: fixed critical
      values, α=0.05 reported, α=0.001 for flagging)
- [x] Avalanche effect — flip 1 plaintext bit, measure % ciphertext bits
      changed; low scores expose diffusion-free designs (XOR ≈ 0.02%),
      randomized ciphers pass trivially by construction
- [ ] Key sensitivity — flip 1 bit in key, measure % of ciphertext bits
      changed; needs a generic re-keying hook on adapted/decorated
      instances (key lives in provider/config, not per-call)
- [x] Pattern detection — ECB canary: repeated ciphertext blocks under
      repetitive plaintext (catches AES-ECB: 63/63 duplicates)
- [x] `ComposerSession.analyze()` / `analyze_all()` (probes bypass session
      metrics), `ReportBuilder.analysis_table()`, `task analyze`,
      `task ride:full --analyze`

### Throughput
- [x] MB/sec throughput metric alongside ops/sec (in `compare()` /
      comparison table)

### Timing Consistency
- [ ] Coefficient of variation (stddev/mean) — flags potential timing side-channels
- [ ] Timing variance by input content — constant-time implementations should show low CV regardless of data


## Lab Office (Site)

Goal: serve the notebooks as a crisp, low-maintenance site, with room for
rich notebooks, exercises, and a cryptography on-ramp mathematics track.

### Stack Decision
- [x] Pin the stack — **Quarto** (v1.9.38, user-local install): renders
      committed `.ipynb` outputs without re-executing (friendliest to our
      outputs-in-git convention), single binary + one `_quarto.yml`,
      native KaTeX for the math track; rich tables render as styled HTML
      `<pre>` blocks with no extra plumbing
- ~~Runner-up: MyST/Jupyter Book 2~~ — revisit only if Quarto theming
  disappoints
- ~~Next.js/Vite~~ — notebooks become second-class (own the ipynb→MDX
  pipeline, ANSI, math, highlighting); only worth it if the site becomes a
  product. Notebooks stay canonical so migration remains possible.

### Candidate A — Root Project (LIVE)
- [x] `_quarto.yml` at repo root; notebooks stay where they are, listed as
      render targets — zero import breakage, minimal churn
- [x] Index page (`index.qmd`): front desk with wings, specimen shelf, lab ops
- [x] Build/preview wired: `task site:build`, `task site:preview`
- [x] Theme pass (`assets/lab.css`): cell outputs render on a terminal-style
      dark panel in both themes, so rich's ANSI palette stays legible; ANSI
      navy lifted for contrast; navbar logo + favicon derived from
      PyCryption.png into `assets/` (trimmed, 104K/8K vs the 2.3M original)
- [ ] Title/heading audit: each notebook's first markdown cell becomes its
      page title — make them consistent

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
- [x] Benchmark persistence (`lib/notebook/persistence.py`): stamped JSON
      records in `benchmarks/` (commit + dirty flag, machine fingerprint,
      UTC timestamp, seed, optional analysis panel); `task bench:save`,
      `task bench:list`, `task bench:diff` (throughput deltas between runs)
- [ ] Surface saved runs on the site (benchmarks page fed from
      `benchmarks/*.json`)

---

## Utilities

- [x] Expand `DataGenerator` with binary data generation (not just ASCII)
- [x] Add deterministic seeded generation for reproducible benchmarks
      (`seed` on DataGenerator, `benchmark()`, and ComposerSession
      benchmark/benchmark_all — per-size payloads derived from the seed)
