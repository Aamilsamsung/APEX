"""Local ACME job lifecycle contract; no privileged Certbot calls."""
import pytest
from fastapi.testclient import TestClient
from backend import core
from backend.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "CERTS", tmp_path / "certificates")
    monkeypatch.setattr(core, "DB", tmp_path / "aegis.db")
    monkeypatch.setenv("AEGIS_OPERATOR_TOKEN", "test-operator-only")
    monkeypatch.setenv("AEGIS_WORKER_TOKEN", "test-worker-only")
    core.seed()
    return TestClient(app)


@pytest.mark.parametrize("success", [True, False])
def test_acme_job_completion_reports_truthful_incident_state(client, success):
    cert = next(c for c in core.inventory() if c["hostname"] == "service-01.demo.local")
    incident = core.simulate_compromise(cert["id"])
    operator = {"X-Aegis-Operator-Token": "test-operator-only"}
    worker = {"X-Aegis-Worker-Token": "test-worker-only"}
    approved = client.post(f"/api/incidents/{incident}/approve-local-acme",
        json={"approver": "Demo Operator", "hostname": "service-01.demo.local"},
        headers=operator)
    assert approved.status_code == 200, approved.text
    job = approved.json()["job_id"]
    assert client.post(f"/api/worker/jobs/{job}/claim", headers=worker).status_code == 200
    completed = client.post(f"/api/worker/jobs/{job}/complete",
        json={"ok": success, "details": "Synthetic worker outcome; no Certbot executed"},
        headers=worker)
    assert completed.status_code == 200, completed.text
    state = next(i for i in core.incidents() if i["id"] == incident)
    assert state["status"] == ("acme_issued_unverified_deployment" if success else "failed")
    titles = [s["title"] for s in core.remediation_steps(incident)["steps"]]
    assert "Local ACME recovery approved" in titles
    assert ("ACME certificate issued locally" if success else "Local ACME recovery failed") in titles
    assert "Certificate properties verified" not in titles
    assert "Old certificate revoked in sandbox registry" not in titles


def test_acme_approval_requires_operator(client):
    cert = next(c for c in core.inventory() if c["hostname"] == "service-01.demo.local")
    incident = core.simulate_compromise(cert["id"])
    response = client.post(f"/api/incidents/{incident}/approve-local-acme",
        json={"approver": "Demo Operator"})
    assert response.status_code == 401
