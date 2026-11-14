"""Explicit LangGraph orchestration for authorized AEGIS PKI sandbox operations.

The approval boundary is enforced by the existing database state machine:
the responder graph is invoked ONLY from the approve endpoint, never by scans.
"""
from __future__ import annotations
from typing import TypedDict, Any
from langgraph.graph import StateGraph, START, END
from . import core

class PKIState(TypedDict, total=False):
    mode: str
    certificate_id: str
    incident_id: str
    approver: str
    inventory_count: int
    inventory: list[dict[str, Any]]
    endpoint_observation: dict[str, Any]
    endpoint_scan_status: str
    findings_count: int
    health: int
    status: str
    result: dict[str, Any]

def scanner(state: PKIState) -> dict:
    core.audit('agent.scanner.started', {'mode':state.get('mode','preventive')})
    inventory = core.inventory()
    endpoint = core.observe_registered_endpoint()
    core.audit('agent.scanner.completed', {'certificates':len(inventory),
               'endpoint_status':endpoint['status'],'next':'risk_analyst'})
    return {'inventory':inventory,'inventory_count':len(inventory),
            'endpoint_observation':endpoint,'endpoint_scan_status':endpoint['status']}

def analyst(state: PKIState) -> dict:
    result=core.scan(state['inventory'])
    findings=core.findings()
    ct = core.ct_monitor()
    endpoint = state['endpoint_observation']
    if endpoint['status']=='observed':
        expected=next((cert for cert in state['inventory'] if cert['hostname']=='service-01.demo.local'
                       and cert['source']!='uploaded-public-cert'), None)
        mismatch=expected is None or not endpoint['fingerprint'].startswith(expected['fingerprint'])
        if mismatch or not endpoint['chain_valid'] or not endpoint['hostname_valid'] or endpoint['revoked']:
            core.audit('agent.risk_analyst.endpoint_risk', {
                'endpoint':endpoint['endpoint'],'serial':endpoint['serial'],'inventory_mismatch':mismatch,
                'chain_valid':endpoint['chain_valid'],'hostname_valid':endpoint['hostname_valid'],
                'revoked':endpoint['revoked'],'rationale':'The served certificate failed sandbox deployment checks',
            })
    core.audit('agent.risk_analyst.completed', {
        'findings': len(findings), 'health': result['health'],
        'ct_mode': 'mock CT replay',
        'suspected_ct_entries': [entry['id'] for entry in ct if entry['status'] == 'suspected_rogue'],
    })
    return {'findings_count':len(findings),'health':result['health'],'status':'scanned'}

def detect(state: PKIState) -> dict:
    incident_id=core.simulate_compromise(state['certificate_id'])
    core.audit('agent.detector.handoff',{'incident_id':incident_id,'next':'human_approval'})
    return {'incident_id':incident_id,'status':'pending_approval'}

def approval_gate(state: PKIState) -> dict:
    # Intentionally stop the graph: an unauthenticated scan cannot execute a response.
    core.audit('agent.approval_gate.paused',{'incident_id':state['incident_id']})
    return {'status':'pending_approval'}

def responder(state: PKIState) -> dict:
    # core.approve_and_remediate atomically checks pending approval and performs the
    # sandbox-only revocation/rotation/redeployment checks.
    result=core.approve_and_remediate(state['incident_id'],state['approver'])
    core.audit('agent.responder.completed',{'incident_id':state['incident_id']})
    return {'result':result,'status':'remediated'}

def _compile(nodes, edges):
    graph=StateGraph(PKIState)
    for name,fn in nodes: graph.add_node(name,fn)
    for source,target in edges: graph.add_edge(source,target)
    return graph.compile()

PREVENTIVE=_compile(
    [('scanner',scanner),('risk_analyst',analyst)],
    [(START,'scanner'),('scanner','risk_analyst'),('risk_analyst',END)])
DETECTION=_compile(
    [('detector',detect),('approval_gate',approval_gate)],
    [(START,'detector'),('detector','approval_gate'),('approval_gate',END)])
RESPONSE=_compile(
    [('responder',responder)],[(START,'responder'),('responder',END)])

def preventive_scan() -> dict:
    with core.LOCK:
        state=PREVENTIVE.invoke({'mode':'preventive'})
    return {key:value for key,value in state.items() if key not in ('inventory','endpoint_observation')}

def simulate_incident(certificate_id: str) -> dict:
    return DETECTION.invoke({'mode':'reactive','certificate_id':certificate_id})

def approved_response(incident_id: str, approver: str) -> dict:
    return RESPONSE.invoke({'mode':'reactive','incident_id':incident_id,'approver':approver})
