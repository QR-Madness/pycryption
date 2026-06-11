# PyCryption

An encryption research repository with specialized composers for demonstrating algorithms and production mechanisms while collecting benchmarks.

> Architect's Note: This repo is an evolving early-prototype. It will lack and/or provide features preferred by cryptography professionals.

## Purpose

This project reduces cognitive overhead when testing:
- Implementable encryption patterns
- Prototype algorithms
- KDF (Key Derivation Function) designs
- Production-ready encryption mechanisms

## Composers

Composers are high-level encryption algorithm harnesses that manage lifecycle, collect metrics, and simplify experimentation:

- **SimpleEncryptionComposer** - Single algorithm with "fire and forget" semantics
- **MultiEncryptionComposer** (prototype) - Layered multi-algorithm encryption

## Getting Started

```bash
# Install dependencies
uv sync

# Run tests
python -m pytest lib/tests/

# Launch notebooks
jupyter notebook
```

## Lab Ops

Day-to-day operations run through [Task](https://taskfile.dev) — no IDE required:

```bash
task            # list all lab tasks
task test       # full test suite
task ride       # benchmark the specimen shelf in the terminal
task ride:full  # include scaling analysis
task nb:check   # execute notebooks headlessly without writing outputs
task nb:exec    # re-execute notebooks, refreshing committed outputs
task analyze    # output quality panel (entropy, avalanche, ECB canary)
task bench:save # persist a seeded, commit-stamped benchmark run
task bench:diff # throughput delta between the latest two saved runs
```

## Notebooks

- `Symmetric.ipynb` - Symmetric encryption benchmarks
- `Asymmetric.ipynb` - Asymmetric encryption examples
- `ML-KEM.ipynb` - Post-quantum hybrid encryption (ML-KEM-768 + AES-256-GCM, FIPS 203)
- `Encryption Composer.ipynb` - Composer usage examples

## Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) package manager
