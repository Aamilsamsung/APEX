from __future__ import annotations
import os, ssl, threading, time
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from . import core

app=FastAPI(title='AEGIS PKI',version='0.1.0',description='Authorized local PKI sandbox demonstration')

@app.on_event('startup')
def startup():
    core.seed()
    core.scan()
    interval=int(os.environ.get('AEGIS_SCAN_INTERVAL_SECONDS','0'))
    if interval>=30:
        def periodic_scans():
            while True:
                time.sleep(interval)
                try: core.scan()
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
def scan(): return core.scan()
class CertificateImport(BaseModel):
    hostname: str
    pem: str

@app.post('/api/certificates/import')
def import_certificate(body: CertificateImport):
    try:
        return core.import_public_certificate(body.pem, body.hostname)
    except ValueError as exc:
        raise HTTPException(400,str(exc))

class Compromise(BaseModel):
    certificate_id:str
@app.post('/api/simulate-compromise')
def compromise(body:Compromise):
    try: return {'incident_id':core.simulate_compromise(body.certificate_id)}
    except ValueError as e: raise HTTPException(400,str(e))
class Approval(BaseModel):
    approver:str
@app.post('/api/incidents/{incident_id}/approve')
def approve(incident_id:str,body:Approval):
    try: return core.approve_and_remediate(incident_id,body.approver)
    except ValueError as e: raise HTTPException(400,str(e))
@app.post('/api/incidents/{incident_id}/reject')
def reject(incident_id:str):
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
def scan_endpoint(body:Endpoint):
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
def scan_local_tls():
    try: return core.scan_registered_endpoint()
    except (ValueError,OSError,ssl.SSLError) as exc: raise HTTPException(400,str(exc))
