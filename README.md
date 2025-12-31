# PyCryption

An encryption research repository with specialized composers for demonstrating algorithms and production mechanisms while collecting benchmarks.

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

## Notebooks

- `Symmetric.ipynb` - Symmetric encryption benchmarks
- `Asymmetric.ipynb` - Asymmetric encryption examples
- `KYBER.ipynb` - Post-quantum key encapsulation
- `Encryption Composer.ipynb` - Composer usage examples

## Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) package manager
