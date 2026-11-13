from __future__ import annotations
import os, ssl, threading, time, secrets
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from . import core, orchestration, openssl_checks, standards

def require_operator(request: Request):
    expected=os.environ.get('AEGIS_OPERATOR_TOKEN','')
    if not expected:
        if os.environ.get('RENDER') or os.environ.get('AEGIS_REQUIRE_OPERATOR_TOKEN')=='1':
            raise HTTPException(503,'Operator token not configured on server')
        return
    provided=request.headers.get('X-Aegis-Operator-Token','')
    if not secrets.compare_digest(provided,expected):
        raise HTTPException(401,'Operator token required')

app=FastAPI(title='AEGIS PKI',version='0.1.0',description='Authorized local PKI sandbox demonstration')

@app.on_event('startup')
def startup():
    core.seed()
    orchestration.preventive_scan()
    if os.environ.get('AEGIS_ENABLE_TLS_DEMO','0')=='1':
        from .demo_tls import serve
        threading.Thread(target=serve,kwargs={'port':8443,'hostname':'service-01.demo.local'},daemon=True,name='aegis-local-tls-demo').start()
    interval=int(os.environ.get('AEGIS_SCAN_INTERVAL_SECONDS','0'))
    if interval>=30:
        def periodic_scans():
            while True:
                time.sleep(interval)
                try: orchestration.preventive_scan()
                except Exception as exc: core.audit('scan.failed',{'error':type(exc).__name__})
        threading.Thread(target=periodic_scans,daemon=True,name='aegis-preventive-scanner').start()

@app.get('/api/health')
def health(): return {'ok':True,'sandbox':True}
@app.get('/api/overview')
def overview(): return core.summary()
@app.get('/api/certificates')
def certificates(): return core.inventory()
@app.get('/api/findings')
def findings(): return core.findings()
@app.get('/api/incidents')
def incidents(): return core.incidents()
@app.get('/api/incidents/{incident_id}/steps')
def incident_steps(incident_id:str):
    try: return core.remediation_steps(incident_id)
    except ValueError as e: raise HTTPException(404,str(e))
@app.get('/api/audit')
def audit(): return core.logs()
@app.get('/api/explanations')
def explanations(): return core.explain_with_llm()
@app.post('/api/scan')
def scan(request:Request):
    require_operator(request)
    return orchestration.preventive_scan()
class CertificateImport(BaseModel):
    hostname: str
    pem: str

@app.post('/api/certificates/import')
def import_certificate(body: CertificateImport,request:Request):
    require_operator(request)
    try:
        return core.import_public_certificate(body.pem, body.hostname)
    except ValueError as exc:
        raise HTTPException(400,str(exc))

class Compromise(BaseModel):
    certificate_id:str
@app.post('/api/simulate-compromise')
def compromise(body:Compromise,request:Request):
    require_operator(request)
    try: return orchestration.simulate_incident(body.certificate_id)
    except ValueError as e: raise HTTPException(400,str(e))
class Approval(BaseModel):
    approver:str
@app.post('/api/incidents/{incident_id}/approve')
def approve(incident_id:str,body:Approval,request:Request):
    require_operator(request)
    try: return orchestration.approved_response(incident_id,body.approver)
    except ValueError as e: raise HTTPException(400,str(e))
@app.post('/api/incidents/{incident_id}/reject')
def reject(incident_id:str,request:Request):
    require_operator(request)
    try:
        core.reject(incident_id)
        return {'status':'rejected'}
    except ValueError as e: raise HTTPException(400,str(e))

FRONTEND=Path(__file__).resolve().parent.parent/'frontend'
app.mount('/assets',StaticFiles(directory=FRONTEND),name='assets')
@app.get('/')
def index(): return FileResponse(FRONTEND/'index.html')

class Endpoint(BaseModel):
    host:str='127.0.0.1'
    port:int=8443
    expected_hostname:str='service-01.demo.local'
@app.post('/api/scan-endpoint')
def scan_endpoint(body:Endpoint,request:Request):
    require_operator(request)
    try: return core.scan_tls_endpoint(body.host,body.port,body.expected_hostname)
    except (ValueError,OSError,ssl.SSLError) as exc: raise HTTPException(400,str(exc))
@app.get('/api/revocations')
def revocations():
    with core.connect() as c: return [dict(r) for r in c.execute('SELECT * FROM revoked_serials ORDER BY revoked_at DESC')]

@app.get('/api/audit-integrity')
def audit_integrity(): return core.verify_audit_chain()

@app.get('/api/ct-monitor')
def ct_monitor(): return core.ct_monitor()

@app.post('/api/scan-local-tls')
def scan_local_tls(request:Request):
    require_operator(request)
    try: return core.scan_registered_endpoint()
    except (ValueError,OSError,ssl.SSLError) as exc: raise HTTPException(400,str(exc))

@app.get('/api/certificates/{certificate_id}/openssl')
def openssl_inspection(certificate_id: str):
    try:
        return openssl_checks.inspect_certificate(certificate_id)
    except ValueError as exc:
        raise HTTPException(404,str(exc))
    except RuntimeError as exc:
        raise HTTPException(503,str(exc))

@app.get('/api/orchestration')
def orchestration_status():
    return {'framework':'LangGraph',
            'preventive':['scanner','risk_analyst'],
            'reactive':['detector','approval_gate','responder'],
            'approval_boundary':'Responder runs only after explicit approval endpoint invocation',
            'scope':'local sandbox'}

@app.get('/api/standards')
def standards_references():
    return standards.references()

@app.get('/api/findings/enriched')
def enriched_findings():
    return standards.findings_with_references()

@app.get('/api/integrations')
def integrations():
    return {'acme':{'configured':bool(os.environ.get('AEGIS_ACME_DIRECTORY_URL')), 'mode':'operator-run certbot HTTP-01', 'status':'private ACME directory configured; issuance not yet verified' if os.environ.get('AEGIS_ACME_DIRECTORY_URL') else 'requires external step-ca ACME server and HTTP-01 challenge setup'},
            'notifications':{'configured':bool(os.environ.get('AEGIS_NOTIFY_WEBHOOK_URL')),
                             'channel':'https_webhook'},
            'tls_demo':{'enabled':os.environ.get('AEGIS_ENABLE_TLS_DEMO','0')=='1',
                        'endpoint':'127.0.0.1:8443'}}
