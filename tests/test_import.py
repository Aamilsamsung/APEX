from cryptography import x509
from cryptography.hazmat.primitives import serialization
from backend import core

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
