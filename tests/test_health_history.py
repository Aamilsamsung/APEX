"""Health score history uses real scan audit snapshots."""
from backend import core
import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "CERTS", tmp_path / "certificates")
    monkeypatch.setattr(core, "DB", tmp_path / "aegis.db")
    core.seed()


def test_history_records_actual_scan_score():
    assert core.health_history() == []
    result = core.scan()
    history = core.health_history()
    assert len(history) == 1
    assert history[0]["health"] == result["health"]
    assert history[0]["timestamp"]


def test_history_preserves_changes_and_limits():
    core.scan()
    cert = core.inventory()[0]
    core.simulate_compromise(cert["id"])
    core.scan()
    history = core.health_history()
    assert len(history) == 2
    assert history[1]["health"] <= history[0]["health"]
    assert core.health_history(1) == history[-1:]
