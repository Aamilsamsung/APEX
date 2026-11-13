from backend import orchestration

def test_graph_has_expected_nodes():
    assert {'scanner','risk_analyst'}.issubset(orchestration.PREVENTIVE.nodes)
    assert {'detector','approval_gate'}.issubset(orchestration.DETECTION.nodes)
    assert 'responder' not in orchestration.DETECTION.nodes
    assert 'responder' in orchestration.RESPONSE.nodes

def test_preventive_graph(monkeypatch):
    from backend import core
    monkeypatch.setattr(core,'scan',lambda:{'total':30,'health':90})
    monkeypatch.setattr(core,'findings',lambda:[{'code':'expiry'}])
    monkeypatch.setattr(core,'audit',lambda *args,**kwargs:None)
    state=orchestration.preventive_scan()
    assert state['inventory_count']==30
    assert state['findings_count']==1
    assert state['health']==90
