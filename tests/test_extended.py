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
    # Show the real webhook outcome alongside any clearly labeled simulation.
    assert any(t in titles for t in (
        'Owner notification delivered',
        'Owner notification not configured',
        'Owner notification failed',
    ))
    if 'Owner notification not configured' in titles:
        assert 'Owner notification simulated' in titles
        assert 'Owner notification delivered' not in titles


def test_required_live_tls_failure_never_marks_incident_resolved(monkeypatch):
    """PS2: failed redeployment verification must not become a successful recovery."""
    cert=next(c for c in core.inventory() if c['hostname']=='service-01.demo.local')
    incident=core.simulate_compromise(cert['id'])
    monkeypatch.setenv('AEGIS_ENABLE_TLS_DEMO','1')
    def unreachable(*args, **kwargs):
        raise OSError('Sandbox TLS endpoint unavailable')
    monkeypatch.setattr(core,'scan_tls_endpoint',unreachable)
    with pytest.raises(RuntimeError,match='TLS deployment verification failed'):
        core.approve_and_remediate(incident,'Demo Operator')
    entry=next(i for i in core.incidents() if i['id']==incident)
    assert entry['status']=='failed'
    assert entry['resolved_at'] is None
    assert not core.verify_revocation(cert['serial'])
    assert next(c for c in core.inventory() if c['hostname']==cert['hostname'])['id']==cert['id']
    assert any(e['action']=='remediation.deployment_verification_failed' for e in core.logs())
    assert any(e['action']=='remediation.rolled_back' for e in core.logs())


def test_file_only_remediation_is_labeled_registry_only(monkeypatch):
    monkeypatch.setenv('AEGIS_ENABLE_TLS_DEMO','0')
    cert=next(c for c in core.inventory() if c['hostname']!='service-01.demo.local')
    incident=core.simulate_compromise(cert['id'])
    result=core.approve_and_remediate(incident,'Demo Operator')
    assert result['status']=='resolved'
    assert result['tls_verification']['status']=='sandbox_registry_only'
    events=[entry['action'] for entry in core.logs()]
    assert 'remediation.registry_updated' in events
    assert 'remediation.deployment_verified' not in events


def test_renewal_requires_policy_finding_and_human_approval():
    cert=next(c for c in core.inventory() if core.assess(c) and c['source']!='uploaded-public-cert')
    requested=core.request_certificate_renewal(cert['id'])
    assert requested['status']=='pending_approval'
    assert requested['finding_codes']
    assert not core.verify_revocation(cert['serial'])
    assert next(i for i in core.incidents() if i['id']==requested['incident_id'])['status']=='pending_approval'
    result=core.approve_and_remediate(requested['incident_id'],'Approved Operator')
    assert result['status']=='resolved'
    assert core.verify_revocation(cert['serial'])
    replacement=next(c for c in core.inventory() if c['id']==result['new_certificate_id'])
    assert replacement['hostname']==cert['hostname']
    assert replacement['serial']!=cert['serial']
    assert not replacement['revoked']
    assert not core.assess(replacement)


def test_healthy_certificate_cannot_be_needlessly_renewed():
    cert=next(c for c in core.inventory() if not core.assess(c))
    with pytest.raises(ValueError,match='no detected policy findings'):
        core.request_certificate_renewal(cert['id'])
