#!/usr/bin/env python
"""
Browse and compare persisted benchmark runs (see scripts/ride.py --save).

Usage:
    python scripts/bench.py list           # all saved runs
    python scripts/bench.py diff           # latest two runs
    python scripts/bench.py diff OLD NEW   # specific run files
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.notebook import ReportBuilder, compare_runs, load_runs


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark run history.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list saved runs")
    diff = sub.add_parser("diff", help="throughput delta between two runs")
    diff.add_argument("runs", nargs="*", help="two run files (default: latest two)")
    args = parser.parse_args()

    report = ReportBuilder()
    runs = load_runs()

    if args.command == "list":
        if not runs:
            report.info("No saved runs yet — try: task bench:save")
            return 0
        rows = [
            {
                "saved_at": r["saved_at"],
                "commit": (r["git"]["commit"] or "?") + ("-dirty" if r["git"]["dirty"] else ""),
                "host": r["machine"]["hostname"],
                "label": r.get("label") or "-",
                "algorithms": len(r.get("benchmarks", {})),
                "file": os.path.basename(r["_path"]),
            }
            for r in runs
        ]
        report.table(rows, columns=list(rows[0].keys()), title="Saved Benchmark Runs")
        return 0

    # diff
    if args.runs:
        if len(args.runs) != 2:
            parser.error("diff takes exactly two run files (or none for latest two)")
        old, new = (json.load(open(p)) for p in args.runs)
    else:
        if len(runs) < 2:
            report.info("Need at least two saved runs to diff.")
            return 1
        old, new = runs[-2], runs[-1]

    report.heading(
        f"Throughput delta: {old['saved_at']} ({old['git']['commit']}) → "
        f"{new['saved_at']} ({new['git']['commit']})",
        level=2,
    )
    rows = compare_runs(old, new)
    if not rows:
        report.info("No overlapping (algorithm, size) pairs between runs.")
        return 1
    report.table(
        rows,
        columns=["algorithm", "size_bytes", "old_throughput_mbps", "new_throughput_mbps", "delta_pct"],
        title="Throughput Delta",
        column_labels={
            "algorithm": "Algorithm",
            "size_bytes": "Size (B)",
            "old_throughput_mbps": "Old (MB/s)",
            "new_throughput_mbps": "New (MB/s)",
            "delta_pct": "Δ %",
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
