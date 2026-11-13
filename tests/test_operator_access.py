from fastapi.testclient import TestClient
from backend.main import app
from backend import core
import pytest

def test_mutations_require_token_on_render(monkeypatch):
    monkeypatch.setenv('RENDER','true')
    monkeypatch.delenv('AEGIS_OPERATOR_TOKEN',raising=False)
    with TestClient(app) as client:
        response=client.post('/api/scan')
        assert response.status_code==503
        assert client.get('/api/health').status_code==200

def test_wrong_token_is_rejected(monkeypatch):
    monkeypatch.setenv('AEGIS_OPERATOR_TOKEN','test-operator-token-123')
    with TestClient(app) as client:
        assert client.post('/api/scan').status_code==401
        assert client.post('/api/scan',headers={'X-Aegis-Operator-Token':'wrong'}).status_code==401

def test_authorized_scan(monkeypatch):
    monkeypatch.setenv('AEGIS_OPERATOR_TOKEN','test-operator-token-123')
    with TestClient(app) as client:
        response=client.post('/api/scan',headers={'X-Aegis-Operator-Token':'test-operator-token-123'})
        assert response.status_code==200
        assert response.json()['status']=='scanned'
