#!/usr/bin/env python
"""
Execute notebooks headlessly via nbclient.

Default mode writes refreshed outputs back into the .ipynb files
(deliberate output regeneration — review the diff before committing).
--check mode executes without writing, for CI smoke tests.

Usage:
    python scripts/exec_notebooks.py                  # all root notebooks, in place
    python scripts/exec_notebooks.py ML-KEM.ipynb     # one notebook
    python scripts/exec_notebooks.py --check          # validate only, no writes
"""
import argparse
import sys
import time
from pathlib import Path

import nbformat
from nbclient import NotebookClient

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute notebooks headlessly.")
    parser.add_argument("notebooks", nargs="*", help="notebook paths (default: all in repo root)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="execute without writing outputs back (CI smoke test)",
    )
    parser.add_argument("--timeout", type=int, default=600, help="per-cell timeout in seconds")
    args = parser.parse_args()

    paths = (
        [Path(p) for p in args.notebooks]
        if args.notebooks
        else sorted(ROOT.glob("*.ipynb"))
    )

    failures: list[str] = []
    for path in paths:
        start = time.perf_counter()
        nb = nbformat.read(path, as_version=4)
        try:
            # resources cwd keeps `from lib...` imports working for all notebooks
            NotebookClient(
                nb,
                timeout=args.timeout,
                kernel_name="python3",
                resources={"metadata": {"path": str(ROOT)}},
            ).execute()
        except Exception as exc:  # noqa: BLE001 — report and continue to next notebook
            failures.append(path.name)
            print(f"✗ {path.name}: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}")
            continue
        elapsed = time.perf_counter() - start
        if not args.check:
            nbformat.write(nb, path)
        print(f"✓ {path.name} ({elapsed:.1f}s{', not written' if args.check else ''})")

    if failures:
        print(f"\n{len(failures)} notebook(s) failed: {', '.join(failures)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
