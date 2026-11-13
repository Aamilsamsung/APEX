"""End-to-end authorized sandbox incident test, including live loopback TLS rotation."""
import threading
import time
import pytest
from fastapi.testclient import TestClient
from backend import core
from backend.demo_tls import serve
from backend.main import app

def test_complete_sandbox_incident_with_live_tls(monkeypatch, tmp_path):
    monkeypatch.setattr(core, 'DATA', tmp_path)
    monkeypatch.setattr(core, 'CERTS', tmp_path / 'certificates')
    monkeypatch.setattr(core, 'DB', tmp_path / 'aegis.db')
    monkeypatch.setenv('AEGIS_OPERATOR_TOKEN','test-token')
    monkeypatch.delenv('AEGIS_NOTIFY_WEBHOOK_URL',raising=False)
    core.seed()
    old=next(c for c in core.inventory() if c['hostname']=='service-01.demo.local')
    thread=threading.Thread(target=serve,kwargs={'port':8443,'hostname':'service-01.demo.local'},daemon=True)
    thread.start()
    for _ in range(40):
        try:
            before=core.scan_tls_endpoint('127.0.0.1',8443,'service-01.demo.local')
            break
        except OSError:
            time.sleep(.1)
    else:
        pytest.fail('TLS demo server did not start')
    assert before['chain_valid'] and before['hostname_valid']
    headers={'X-Aegis-Operator-Token':'test-token'}
    with TestClient(app) as client:
        assert client.post('/api/simulate-compromise',json={'certificate_id':old['id']}).status_code==401
        detection=client.post('/api/simulate-compromise',headers=headers,json={'certificate_id':old['id']})
        assert detection.status_code==200,detection.text
        incident_id=detection.json()['incident_id']
        pending=next(i for i in client.get('/api/incidents').json() if i['id']==incident_id)
        assert pending['status']=='pending_approval'
        response=client.post(f'/api/incidents/{incident_id}/approve',headers=headers,json={'approver':'CI Operator'})
        assert response.status_code==200,response.text
        resolved=next(i for i in client.get('/api/incidents').json() if i['id']==incident_id)
        assert resolved['status']=='resolved'
        after=core.scan_tls_endpoint('127.0.0.1',8443,'service-01.demo.local')
        assert after['serial']!=before['serial']
        assert after['chain_valid'] and after['hostname_valid'] and not after['revoked']
        assert core.verify_revocation(before['serial'])
        assert client.get('/api/audit-integrity').json()['valid']
        steps=client.get(f'/api/incidents/{incident_id}/steps').json()
        assert steps['deployment']['status']=='verified'
