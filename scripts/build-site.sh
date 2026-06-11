#!/usr/bin/env bash
# Self-contained site build — works locally and on CI/Vercel images that
# have neither Quarto nor uv preinstalled. Idempotent: reuses existing
# tools and the synced venv when present.
set -euo pipefail

QUARTO_VERSION="${QUARTO_VERSION:-1.9.38}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- Quarto ---------------------------------------------------------------
if ! command -v quarto >/dev/null 2>&1; then
  echo "Installing Quarto ${QUARTO_VERSION}..."
  curl -sL "https://github.com/quarto-dev/quarto-cli/releases/download/v${QUARTO_VERSION}/quarto-${QUARTO_VERSION}-linux-amd64.tar.gz" \
    | tar xz -C /tmp
  export PATH="/tmp/quarto-${QUARTO_VERSION}/bin:$PATH"
fi
quarto --version

# --- uv + Python env (needed: benchmarks.qmd executes at build) -----------
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
uv sync --frozen
export QUARTO_PYTHON="$REPO_ROOT/.venv/bin/python"

# --- Render ----------------------------------------------------------------
quarto render
echo "Site built to _site/"
