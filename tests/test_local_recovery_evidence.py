from fastapi.testclient import TestClient
from backend import main, core
import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "CERTS", tmp_path / "certificates")
    monkeypatch.setattr(core, "DB", tmp_path / "aegis.db")
    monkeypatch.setenv("AEGIS_OPERATOR_TOKEN", "test-only-operator-token")
    core.init_db()


def test_evidence_requires_operator_and_records_audit():
    client=TestClient(main.app)
    payload={"hostname":"service-01.demo.local","old_serial":"ABCD","new_serial":"DCBA",
             "sha256_fingerprint":"a"*64,"deployment_verified":True,
             "ca_revocation_confirmed":True,"operator":"demo operator"}
    assert client.post("/api/local-recovery/evidence",json=payload).status_code==401
    response=client.post("/api/local-recovery/evidence",json=payload,
                         headers={"X-Aegis-Operator-Token":"test-only-operator-token"})
    assert response.status_code==200
    evidence=client.get("/api/local-recovery/evidence").json()
    assert evidence["available"] is True
    assert evidence["evidence"]["evidence_type"]=="operator_attestation"
    assert core.verify_audit_chain()["valid"]


def test_evidence_rejects_invalid_or_identical_serials():
    client=TestClient(main.app)
    payload={"old_serial":"AB","new_serial":"AB","sha256_fingerprint":"b"*64,
             "deployment_verified":True,"ca_revocation_confirmed":False,"operator":"tester"}
    response=client.post("/api/local-recovery/evidence",json=payload,
                         headers={"X-Aegis-Operator-Token":"test-only-operator-token"})
    assert response.status_code==400
