"""Tests for ComposerSession."""
import os

import pytest

from lib.notebook.composer import AlgorithmMetrics, ComposerSession
from lib.notebook.decorators import algorithm, with_key


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


def _make_algo(key: bytes, name: str = "TestAlgo"):
    @algorithm(name)
    @with_key(key)
    class Algo:
        def encrypt(self, data: bytes, ctx) -> bytes:
            return data[::-1]

        def decrypt(self, data: bytes, ctx) -> bytes:
            return data[::-1]

    return Algo()


class TestComposerRegistration:
    def test_register_and_list(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key, "A"))
        session.register(_make_algo(key, "B"))
        assert set(session.list_algorithms()) == {"A", "B"}

    def test_register_returns_self_for_chaining(self, key: bytes) -> None:
        session = ComposerSession()
        result = session.register(_make_algo(key))
        assert result is session

    def test_get_registered_algorithm(self, key: bytes) -> None:
        session = ComposerSession()
        algo = _make_algo(key)
        session.register(algo)
        assert session.get("TestAlgo") is algo

    def test_get_missing_algorithm_raises(self) -> None:
        session = ComposerSession()
        with pytest.raises(KeyError, match="not registered"):
            session.get("missing")

    def test_override_name(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key, "Original"), name="Override")
        assert "Override" in session.list_algorithms()
        assert "Original" not in session.list_algorithms()


class TestComposerEncryptDecrypt:
    def test_encrypt(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key))
        result = session.encrypt("TestAlgo", b"hello")
        assert result.success
        assert result.output == b"olleh"

    def test_decrypt(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key))
        result = session.decrypt("TestAlgo", b"olleh")
        assert result.success
        assert result.output == b"hello"


class TestComposerTest:
    def test_round_trip_passes(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key))
        assert session.test("TestAlgo") is True

    def test_test_all(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key, "A"))
        session.register(_make_algo(key, "B"))
        results = session.test_all()
        assert results == {"A": True, "B": True}


class TestComposerMetrics:
    def test_report_structure(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key))
        session.encrypt("TestAlgo", b"x")
        session.decrypt("TestAlgo", b"x")

        report = session.report()
        assert "TestAlgo" in report
        entry = report["TestAlgo"]
        assert entry["encrypt_calls"] == 1
        assert entry["decrypt_calls"] == 1

    def test_reset_metrics(self, key: bytes) -> None:
        session = ComposerSession()
        session.register(_make_algo(key))
        session.encrypt("TestAlgo", b"x")
        session.reset_metrics()

        report = session.report()
        assert report["TestAlgo"]["encrypt_calls"] == 0


class TestAlgorithmMetricsDataclass:
    def test_avg_encrypt_ms(self) -> None:
        m = AlgorithmMetrics(name="t", encrypt_calls=2, total_encrypt_ms=10.0)
        assert m.avg_encrypt_ms == 5.0

    def test_avg_decrypt_ms(self) -> None:
        m = AlgorithmMetrics(name="t", decrypt_calls=4, total_decrypt_ms=8.0)
        assert m.avg_decrypt_ms == 2.0

    def test_avg_with_zero_calls(self) -> None:
        m = AlgorithmMetrics(name="t")
        assert m.avg_encrypt_ms == 0.0
        assert m.avg_decrypt_ms == 0.0

    def test_as_dict(self) -> None:
        m = AlgorithmMetrics(name="t", encrypt_calls=1, total_encrypt_ms=1.5)
        d = m.as_dict()
        assert d["name"] == "t"
        assert d["avg_encrypt_ms"] == 1.5
