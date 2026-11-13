import pytest
from backend import core

@pytest.fixture(autouse=True)
def sandbox(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'DATA',tmp_path)
    monkeypatch.setattr(core,'CERTS',tmp_path/'certificates')
    monkeypatch.setattr(core,'DB',tmp_path/'aegis.db')
    core.seed()

def test_sandbox_ca_signs_all_certificates():
    assert all(c['chain_valid'] for c in core.inventory())

def test_revocation_registry_after_approval():
    cert=core.inventory()[0]
    incident=core.simulate_compromise(cert['id'])
    core.approve_and_remediate(incident,'Operator')
    assert core.verify_revocation(cert['serial'])
    replacement=next(c for c in core.inventory() if c['hostname']==cert['hostname'])
    assert replacement['chain_valid'] and replacement['serial'] != cert['serial']
    assert not core.verify_revocation(replacement['serial'])

def test_nonlocal_endpoint_is_rejected():
    with pytest.raises(ValueError): core.scan_tls_endpoint('example.com',443,'example.com')

def test_no_llm_is_explicit_fallback(monkeypatch):
    monkeypatch.delenv('GROQ_API_KEY',raising=False)
    core.scan()
    assert core.explain_with_llm()['mode']=='deterministic-fallback'

def test_incident_steps_describe_real_sandbox_actions():
    cert=core.inventory()[0]
    incident=core.simulate_compromise(cert['id'])
    pending=core.remediation_steps(incident)
    assert pending['status']=='pending_approval'
    assert 'Compromise detected' in pending['steps'][0]['title']
    core.approve_and_remediate(incident,'Demo Operator')
    result=core.remediation_steps(incident)
    assert result['status']=='resolved'
    titles=[s['title'] for s in result['steps']]
    assert 'Fresh private key generated' in titles
    assert 'Owner notification simulated' in titles
