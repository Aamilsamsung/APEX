import pytest
from backend import core

@pytest.fixture(autouse=True)
def sandbox(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'DATA',tmp_path)
    monkeypatch.setattr(core,'CERTS',tmp_path/'certificates')
    monkeypatch.setattr(core,'DB',tmp_path/'aegis.db')
    core.seed()

def test_seed_inventory():
    assert len(core.inventory())==30
    assert core.seed() is False

def test_scan_and_findings():
    summary=core.scan()
    assert summary['total']==30
    assert 0<summary['health']<100
    assert any(f['code']=='WEAK_RSA' for f in core.findings())
    assert any(f['code']=='HOSTNAME_MISMATCH' for f in core.findings())
    assert any(f['code']=='EXPIRED' for f in core.findings())

def test_remediation_requires_approval():
    core.scan()
    cert=core.inventory()[0]
    incident=core.simulate_compromise(cert['id'])
    assert any(f['code']=='KEY_COMPROMISE' and f['certificate_id']==cert['id'] for f in core.findings())
    assert core.incidents()[0]['status']=='pending_approval'
    assert core.inventory()[0]['id']==cert['id']
    with pytest.raises(ValueError): core.approve_and_remediate(incident,'')
    result=core.approve_and_remediate(incident,'Test Operator')
    assert result['status']=='resolved'
    assert core.incidents()[0]['status']=='resolved'
    assert not any(f['code']=='KEY_COMPROMISE' for f in core.findings())
    assert len(core.inventory())==30
    assert any(a['action']=='remediation.completed' for a in core.logs())

def test_rejection_does_not_repair():
    cert=core.inventory()[0]
    incident=core.simulate_compromise(cert['id'])
    core.reject(incident)
    assert core.incidents()[0]['status']=='rejected'
    assert any(f['code']=='KEY_COMPROMISE' for f in core.findings())
    with pytest.raises(ValueError): core.approve_and_remediate(incident,'Test Operator')
