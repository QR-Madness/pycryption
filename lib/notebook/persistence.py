# lib/notebook/persistence.py
"""
Benchmark persistence — longitudinal lab records.

Each saved run is one JSON file in ``benchmarks/`` stamped with the git
commit, machine fingerprint, and UTC timestamp, so results are comparable
across time and hardware ("did that refactor cost throughput?"). Files are
meant to be committed; they are the lab's measurement history.

Dependency-free: stdlib only.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks"


def git_state() -> Dict[str, Any]:
    """Current commit (short) and dirty flag; tolerates running outside git."""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, check=True,
        ).stdout.strip())
        return {"commit": commit, "dirty": dirty}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"commit": None, "dirty": None}


def machine_fingerprint() -> Dict[str, Any]:
    """Identify the hardware/runtime a run was measured on."""
    import os

    return {
        "hostname": platform.node(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "system": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def save_benchmark_run(
    benchmarks: Dict[str, Dict[str, Any]],
    *,
    label: Optional[str] = None,
    seed: Optional[Any] = None,
    iterations: Optional[int] = None,
    analysis: Optional[Dict[str, Dict[str, Any]]] = None,
    results_dir: Optional[Path] = None,
) -> Path:
    """
    Persist a ComposerSession.benchmark_all() result as a stamped JSON record.

    Returns the path of the written file
    (``benchmarks/<utc-ts>_<commit>[_label].json``).
    """
    results_dir = Path(results_dir or DEFAULT_RESULTS_DIR)
    results_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    git = git_state()

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "saved_at": now.isoformat(timespec="seconds"),
        "git": git,
        "machine": machine_fingerprint(),
        "seed": str(seed) if seed is not None else None,
        "iterations": iterations,
        "label": label,
        "benchmarks": benchmarks,
    }
    if analysis is not None:
        record["analysis"] = analysis

    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    commit = git["commit"] or "nogit"
    if git["dirty"]:
        commit += "-dirty"
    name = f"{stamp}_{commit}"
    if label:
        name += "_" + re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-")
    path = results_dir / f"{name}.json"

    path.write_text(json.dumps(record, indent=2, sort_keys=False) + "\n")
    return path


def load_runs(results_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load all saved runs, oldest first. Each record gains a ``_path`` key."""
    results_dir = Path(results_dir or DEFAULT_RESULTS_DIR)
    runs = []
    for path in sorted(results_dir.glob("*.json")):
        record = json.loads(path.read_text())
        record["_path"] = str(path)
        runs.append(record)
    runs.sort(key=lambda r: r.get("saved_at") or "")
    return runs


def latest_run(results_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Most recent saved run, or None."""
    runs = load_runs(results_dir)
    return runs[-1] if runs else None


def compare_runs(old: Dict[str, Any], new: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Throughput deltas between two saved runs, per algorithm and size.

    Only (algorithm, size) pairs present in both runs are compared.
    """
    def index(run: Dict[str, Any]) -> Dict[tuple, float]:
        out = {}
        for algo, result in run.get("benchmarks", {}).items():
            for entry in result.get("benchmarks", []):
                out[(algo, entry["size_bytes"])] = entry.get("throughput_mbps", 0.0)
        return out

    old_idx, new_idx = index(old), index(new)
    rows = []
    for key in sorted(old_idx.keys() & new_idx.keys()):
        algo, size = key
        old_tp, new_tp = old_idx[key], new_idx[key]
        delta = round((new_tp - old_tp) / old_tp * 100, 1) if old_tp else None
        rows.append({
            "algorithm": algo,
            "size_bytes": size,
            "old_throughput_mbps": old_tp,
            "new_throughput_mbps": new_tp,
            "delta_pct": delta,
        })
    return rows
