from pathlib import Path

from fastapi.testclient import TestClient
from backend import core
from backend.main import app

def test_public_certificate_import(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'DATA', tmp_path)
    monkeypatch.setattr(core, 'CERTS', tmp_path / 'certificates')
    monkeypatch.setattr(core, 'DB', tmp_path / 'aegis.db')
    core._CA_CACHE.clear()
    core.seed()
    cert = core.inventory()[0]
    with core.connect() as db:
        path = db.execute('SELECT path FROM certificates WHERE id=?', (cert['id'],)).fetchone()['path']
    pem = open(path, encoding='ascii').read()
    imported = core.import_public_certificate(pem, 'imported.demo.local')
    assert imported['source'] == 'uploaded-public-cert'
    assert any(c['id'] == imported['certificate_id'] for c in core.inventory())
    try:
        core.import_public_certificate('-----BEGIN PRIVATE KEY-----', 'bad.demo.local')
        assert False, 'private keys must be rejected'
    except ValueError:
        pass
    try:
        core.simulate_compromise(imported['certificate_id'])
        assert False, 'imported certificate cannot be rotated'
    except ValueError:
        pass


def test_bulk_public_pem_and_read_only_metadata_preview(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'DATA', tmp_path)
    monkeypatch.setattr(core, 'CERTS', tmp_path / 'certificates')
    monkeypatch.setattr(core, 'DB', tmp_path / 'aegis.db')
    monkeypatch.setenv('AEGIS_OPERATOR_TOKEN', 'test-token')
    core.seed()
    with core.connect() as db:
        paths = [row['path'] for row in db.execute('SELECT path FROM certificates LIMIT 2')]
    pem = ''.join(Path(path).read_text() for path in paths)
    client = TestClient(app)
    response = client.post('/api/certificates/import-bulk', json={'pem': pem},
                           headers={'X-Aegis-Operator-Token':'test-token'})
    assert response.status_code == 200
    assert response.json()['imported'] == 2
    audit_before = core.verify_audit_chain()
    preview = client.post('/api/certificates/import-metadata', json={'text':'{"hostname":"preview.demo.local"}'})
    assert preview.status_code == 200
    assert preview.json()['results'][0]['verified'] is False
    assert len(core.inventory()) == 32
    assert core.verify_audit_chain() == audit_before
