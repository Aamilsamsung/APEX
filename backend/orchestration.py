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
    findings_count: int
    health: int
    status: str
    result: dict[str, Any]

def scanner(state: PKIState) -> dict:
    core.audit('agent.scanner.started', {'mode':state.get('mode','preventive')})
    result=core.scan()
    core.audit('agent.scanner.completed', {'certificates':result['total']})
    return {'inventory_count':result['total'],'health':result['health']}

def analyst(state: PKIState) -> dict:
    findings=core.findings()
    core.audit('agent.risk_analyst.completed', {'findings':len(findings),'health':state.get('health')})
    return {'findings_count':len(findings),'status':'scanned'}

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
    return PREVENTIVE.invoke({'mode':'preventive'})

def simulate_incident(certificate_id: str) -> dict:
    return DETECTION.invoke({'mode':'reactive','certificate_id':certificate_id})

def approved_response(incident_id: str, approver: str) -> dict:
    return RESPONSE.invoke({'mode':'reactive','incident_id':incident_id,'approver':approver})
