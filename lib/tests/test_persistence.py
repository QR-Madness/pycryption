"""Tests for benchmark persistence (lib/notebook/persistence.py) and seeded data."""
import json
import os
from pathlib import Path

import pytest

from lib.algorithms import Aes256GcmAlgorithm
from lib.notebook import (
    ComposerSession,
    adapt,
    compare_runs,
    latest_run,
    load_runs,
    save_benchmark_run,
)
from lib.notebook.persistence import git_state, machine_fingerprint
from lib.util.DataGenerator import DataGenerator

KEY = os.urandom(32)


@pytest.fixture
def session() -> ComposerSession:
    s = ComposerSession()
    s.register(adapt(Aes256GcmAlgorithm, KEY, name="AES-256-GCM"))
    return s


class TestSeededGeneration:
    def test_binary_seeded_is_deterministic(self) -> None:
        a = DataGenerator.generate_binary_data(1024, seed="lab")
        b = DataGenerator.generate_binary_data(1024, seed="lab")
        assert a == b

    def test_binary_different_seeds_differ(self) -> None:
        assert DataGenerator.generate_binary_data(1024, seed=1) != \
            DataGenerator.generate_binary_data(1024, seed=2)

    def test_binary_unseeded_differs(self) -> None:
        assert DataGenerator.generate_binary_data(1024) != DataGenerator.generate_binary_data(1024)

    def test_ascii_seeded_is_deterministic(self) -> None:
        a = DataGenerator.generate_ascii_text_data(500, seed="lab")
        b = DataGenerator.generate_ascii_text_data(500, seed="lab")
        assert a == b

    def test_seeded_benchmark_records_seed(self, session: ComposerSession) -> None:
        result = session.benchmark("AES-256-GCM", data_sizes=[256], iterations=2, seed="lab")
        assert result["seed"] == "lab"

    def test_unseeded_benchmark_has_no_seed(self, session: ComposerSession) -> None:
        result = session.benchmark("AES-256-GCM", data_sizes=[256], iterations=2)
        assert "seed" not in result


class TestEnvelope:
    def test_git_state_in_repo(self) -> None:
        state = git_state()
        assert state["commit"] is not None
        assert isinstance(state["dirty"], bool)

    def test_machine_fingerprint_keys(self) -> None:
        fp = machine_fingerprint()
        assert fp["hostname"]
        assert fp["python"]
        assert fp["cpu_count"] >= 1


class TestSaveAndLoad:
    def test_round_trip(self, session: ComposerSession, tmp_path: Path) -> None:
        benchmarks = session.benchmark_all(data_sizes=[256], iterations=2, seed="lab")
        path = save_benchmark_run(
            benchmarks, label="test run", seed="lab", iterations=2, results_dir=tmp_path
        )
        assert path.exists()
        record = json.loads(path.read_text())
        assert record["schema_version"] == 1
        assert record["seed"] == "lab"
        assert record["label"] == "test run"
        assert "AES-256-GCM" in record["benchmarks"]
        assert record["git"]["commit"]
        assert record["machine"]["hostname"]

    def test_label_is_slugged_into_filename(self, session: ComposerSession, tmp_path: Path) -> None:
        benchmarks = session.benchmark_all(data_sizes=[256], iterations=2)
        path = save_benchmark_run(benchmarks, label="post merge / v2!", results_dir=tmp_path)
        assert "post-merge-v2" in path.name
        assert "/" not in path.name.replace(str(tmp_path), "")

    def test_load_runs_sorted(self, session: ComposerSession, tmp_path: Path) -> None:
        benchmarks = session.benchmark_all(data_sizes=[256], iterations=2)
        save_benchmark_run(benchmarks, label="one", results_dir=tmp_path)
        save_benchmark_run(benchmarks, label="two", results_dir=tmp_path)
        runs = load_runs(tmp_path)
        assert len(runs) == 2
        assert runs[0]["saved_at"] <= runs[1]["saved_at"]
        assert all("_path" in r for r in runs)

    def test_latest_run(self, session: ComposerSession, tmp_path: Path) -> None:
        assert latest_run(tmp_path) is None
        benchmarks = session.benchmark_all(data_sizes=[256], iterations=2)
        save_benchmark_run(benchmarks, label="newest", results_dir=tmp_path)
        assert latest_run(tmp_path)["label"] == "newest"

    def test_analysis_payload_included(self, session: ComposerSession, tmp_path: Path) -> None:
        benchmarks = session.benchmark_all(data_sizes=[256], iterations=2)
        path = save_benchmark_run(
            benchmarks,
            analysis=session.analyze_all(sample_size=2048, trials=4),
            results_dir=tmp_path,
        )
        record = json.loads(path.read_text())
        assert record["analysis"]["AES-256-GCM"]["flags"] == []


class TestCompareRuns:
    def _run(self, throughput: float) -> dict:
        return {
            "benchmarks": {
                "AES": {"benchmarks": [{"size_bytes": 1000, "throughput_mbps": throughput}]},
            }
        }

    def test_delta_pct(self) -> None:
        rows = compare_runs(self._run(100.0), self._run(150.0))
        assert rows == [{
            "algorithm": "AES",
            "size_bytes": 1000,
            "old_throughput_mbps": 100.0,
            "new_throughput_mbps": 150.0,
            "delta_pct": 50.0,
        }]

    def test_no_overlap(self) -> None:
        old = self._run(100.0)
        new = {"benchmarks": {"ChaCha": {"benchmarks": [{"size_bytes": 1000, "throughput_mbps": 5}]}}}
        assert compare_runs(old, new) == []

    def test_zero_old_throughput_yields_none(self) -> None:
        rows = compare_runs(self._run(0.0), self._run(10.0))
        assert rows[0]["delta_pct"] is None
