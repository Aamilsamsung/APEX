from backend import core

def test_mock_ct_feed():
    core.seed()
    rows=core.ct_monitor()
    assert any(r['status']=='suspected_rogue' for r in rows)
    assert all(r['source']=='mock CT replay' for r in rows)

def test_audit_integrity():
    core.seed()
    core.audit('test.integrity',{'test':True})
    assert core.verify_audit_chain()['valid']

def test_extended_risk_rules():
    base={'days_remaining':90,'key_type':'RSA','key_bits':2048,'signature':'sha256','hostname':'api.demo.local','sans':['api.demo.local'],'chain_valid':True,'compromised':False,'revoked':False,'self_signed':False,'validity_days':500}
    assert 'LONG_VALIDITY' in {f['code'] for f in core.assess(base)}
    base['self_signed']=True
    assert 'UNEXPECTED_SELF_SIGNED' in {f['code'] for f in core.assess(base)}


def test_audit_integrity_checks_the_displayed_log(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'DATA', tmp_path)
    monkeypatch.setattr(core, 'DB', tmp_path / 'audit.sqlite')
    core.init_db()
    core.audit('test.integrity', {'expected': True})
    assert core.verify_audit_chain()['valid']
    with core.connect() as db:
        db.execute("UPDATE audit SET details = '{}'")
    assert not core.verify_audit_chain()['valid']
