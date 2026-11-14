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
@app.get('/api/health-history')
def health_history(): return core.health_history()
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

class RenewalRequest(BaseModel):
    certificate_id:str

@app.post('/api/certificates/renewal-request')
def request_renewal(body:RenewalRequest,request:Request):
    require_operator(request)
    try: return core.request_certificate_renewal(body.certificate_id)
    except ValueError as exc: raise HTTPException(400,str(exc))

# Separate real-ACME demo request: healthy certificate rotation is permitted only
# for the pinned private demo hostname and still requires explicit approval.
@app.post('/api/certificates/real-acme-request')
def request_real_acme(body:RenewalRequest,request:Request):
    require_operator(request)
    init_worker_jobs()
    with core.LOCK:
        with core.connect() as db:
            cert=db.execute('SELECT * FROM certificates WHERE id=? AND active=1',(body.certificate_id,)).fetchone()
            if not cert or cert['hostname']!='service-01.demo.local' or cert['source']=='uploaded-public-cert':
                raise HTTPException(400,'Only the managed service-01.demo.local certificate supports real ACME demo')
            existing=db.execute("SELECT id FROM incidents WHERE certificate_id=? AND status IN ('pending_approval','approved','executing')",(body.certificate_id,)).fetchone()
            if existing: raise HTTPException(409,'An incident is already pending or running for this certificate')
            incident_id=secrets.token_hex(12)
            db.execute('INSERT INTO incidents(id,certificate_id,type,status,created_at) VALUES(?,?,?,?,?)',
                       (incident_id,body.certificate_id,'REAL_ACME_RENEWAL','pending_approval',core.timestamp()))
        core.audit('real_acme.renewal_requested',{'incident_id':incident_id,'certificate_id':body.certificate_id,'hostname':'service-01.demo.local','note':'Awaiting explicit operator approval; no CA action performed'})
    return {'incident_id':incident_id,'status':'pending_approval'}

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

# Remote worker handshake. A separate token protects this channel.
# This endpoint never exposes CA private keys or accepts arbitrary shell commands.
@app.get('/api/worker/ping')
def worker_ping(request:Request):
    token=os.environ.get('AEGIS_WORKER_TOKEN','')
    provided=request.headers.get('X-Aegis-Worker-Token','')
    if not token or not secrets.compare_digest(provided,token):
        raise HTTPException(401,'Worker token required')
    return {'ok':True,'mode':'connectivity-only','message':'Remote worker authenticated; job execution not enabled'}

# Explicitly authorized local-worker verification jobs.
# Demo queue uses the existing SQLite DB; Render free restarts can erase it.
def require_worker(request:Request):
    expected=os.environ.get('AEGIS_WORKER_TOKEN','')
    if not expected or not secrets.compare_digest(request.headers.get('X-Aegis-Worker-Token',''),expected):
        raise HTTPException(401,'Worker token required')

def init_worker_jobs():
    with core.connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS worker_jobs(
            id TEXT PRIMARY KEY, action TEXT NOT NULL, hostname TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL, result TEXT)''')

@app.post('/api/worker/jobs/test')
def enqueue_worker_test(request:Request):
    require_operator(request)
    init_worker_jobs()
    job_id=secrets.token_hex(12)
    with core.connect() as db:
        db.execute('INSERT INTO worker_jobs(id,action,hostname,status,created_at) VALUES(?,?,?,?,?)',
                   (job_id,'inspect_certificate','service-01.demo.local','queued',core.timestamp()))
    core.audit('worker.job.queued',{'job_id':job_id,'action':'inspect_certificate'})
    return {'id':job_id,'status':'queued','action':'inspect_certificate'}

@app.get('/api/worker/jobs')
def worker_jobs(request:Request):
    require_worker(request)
    init_worker_jobs()
    with core.connect() as db:
        return [dict(row) for row in db.execute('SELECT * FROM worker_jobs ORDER BY created_at DESC LIMIT 20')]

@app.post('/api/worker/jobs/{job_id}/claim')
def worker_claim(job_id:str,request:Request):
    require_worker(request)
    init_worker_jobs()
    with core.connect() as db:
        cur=db.execute("UPDATE worker_jobs SET status='running' WHERE id=? AND status='queued'",(job_id,))
        if not cur.rowcount: raise HTTPException(409,'Job unavailable or already claimed')
    core.audit('worker.job.claimed',{'job_id':job_id})
    return {'id':job_id,'status':'running'}

class WorkerResult(BaseModel):
    ok:bool
    details:str

@app.post('/api/worker/jobs/{job_id}/complete')
def worker_complete(job_id:str,body:WorkerResult,request:Request):
    require_worker(request)
    init_worker_jobs()
    if len(body.details)>2000: raise HTTPException(400,'Result too long')
    with core.connect() as db:
        cur=db.execute("UPDATE worker_jobs SET status=?,result=? WHERE id=? AND status='running'",
                       ('completed' if body.ok else 'failed',body.details,job_id))
        if not cur.rowcount: raise HTTPException(409,'Job not running')
    incident_id=None
    with core.connect() as db:
        job=db.execute('SELECT action,result FROM worker_jobs WHERE id=?',(job_id,)).fetchone()
        if job and job['action']=='acme_recovery':
            # The job's original result field holds the incident id until completion;
            # completion overwrites it, so lookup via the approval audit event.
            import json as _json
            for entry in db.execute("SELECT details FROM audit WHERE action='remediation.local_acme_approved' ORDER BY id DESC"):
                event=_json.loads(entry['details'])
                if event.get('job_id')==job_id:
                    incident_id=event['incident_id']
                    db.execute('UPDATE incidents SET status=?,error=? WHERE id=? AND status="approved"',
                               ('acme_issued_unverified_deployment' if body.ok else 'failed',
                                'Local ACME issuance verified; CA revocation and deployment not performed' if body.ok else body.details,
                                incident_id))
                    break
    core.audit('worker.job.completed',{'job_id':job_id,'action':job['action'] if job else None,'incident_id':incident_id,'ok':body.ok,'details':body.details})
    return {'id':job_id,'status':'completed' if body.ok else 'failed'}


# Operator-attested evidence for a separately performed local CA recovery.
# This records evidence; it cannot execute or claim to verify remote CA operations.
class LocalRecoveryEvidence(BaseModel):
    hostname:str='service-01.demo.local'
    old_serial:str
    new_serial:str
    sha256_fingerprint:str
    deployment_verified:bool
    ca_revocation_confirmed:bool
    operator:str

@app.post('/api/local-recovery/evidence')
def record_local_recovery_evidence(body:LocalRecoveryEvidence,request:Request):
    require_operator(request)
    import re
    if body.hostname!='service-01.demo.local': raise HTTPException(400,'Demo hostname only')
    if not body.operator.strip() or len(body.operator)>100: raise HTTPException(400,'Operator required')
    for serial in (body.old_serial,body.new_serial):
        if not re.fullmatch(r'[0-9a-fA-F]{1,40}',serial): raise HTTPException(400,'Invalid hexadecimal serial')
    if int(body.old_serial,16)==int(body.new_serial,16): raise HTTPException(400,'Serials must differ')
    if not re.fullmatch(r'[0-9a-fA-F]{64}',body.sha256_fingerprint): raise HTTPException(400,'Invalid SHA256 fingerprint')
    event={'hostname':body.hostname,'old_serial':body.old_serial.upper(),
           'new_serial':body.new_serial.upper(),'sha256_fingerprint':body.sha256_fingerprint.lower(),
           'deployment_verified':body.deployment_verified,
           'ca_revocation_confirmed':body.ca_revocation_confirmed,
           'operator':body.operator.strip(),'evidence_type':'operator_attestation',
           'note':'Operator-reported local evidence; cloud server cannot independently inspect the private CA'}
    core.audit('local_recovery.operator_attested',event)
    return {'recorded':True,'evidence':event}

@app.get('/api/local-recovery/evidence')
def local_recovery_evidence():
    import json
    with core.connect() as db:
        row=db.execute("SELECT timestamp,details FROM audit WHERE action='local_recovery.operator_attested' ORDER BY id DESC LIMIT 1").fetchone()
    return {'available':bool(row),'timestamp':row['timestamp'] if row else None,
            'evidence':json.loads(row['details']) if row else None}

# Separate explicit operator authorization for local ACME recovery.
# Does not alter the existing sandbox-only approval route.
class AcmeRecoveryApproval(BaseModel):
    approver:str
    hostname:str='service-01.demo.local'

@app.post('/api/incidents/{incident_id}/approve-local-acme')
def approve_local_acme(incident_id:str,body:AcmeRecoveryApproval,request:Request):
    require_operator(request)
    if not body.approver.strip(): raise HTTPException(400,'Approver required')
    if body.hostname!='service-01.demo.local':
        raise HTTPException(400,'Local ACME demo is restricted to service-01.demo.local')
    init_worker_jobs()
    with core.LOCK:
        with core.connect() as db:
            incident=db.execute('SELECT * FROM incidents WHERE id=? AND status="pending_approval"',(incident_id,)).fetchone()
            if not incident: raise HTTPException(409,'Incident must be pending approval')
            cert=db.execute('SELECT hostname FROM certificates WHERE id=?',(incident['certificate_id'],)).fetchone()
            if not cert or cert['hostname']!=body.hostname:
                raise HTTPException(400,'Incident certificate hostname does not match local ACME target')
            job_id=secrets.token_hex(12)
            db.execute('UPDATE incidents SET status="approved",approved_at=? WHERE id=?',(core.timestamp(),incident_id))
            db.execute('INSERT INTO worker_jobs(id,action,hostname,status,created_at,result) VALUES(?,?,?,?,?,?)',
                       (job_id,'acme_recovery',body.hostname,'queued',core.timestamp(),incident_id))
        core.audit('remediation.local_acme_approved',{'incident_id':incident_id,'job_id':job_id,'approver':body.approver,'hostname':body.hostname})
    return {'job_id':job_id,'incident_id':incident_id,'status':'queued','action':'acme_recovery',
            'note':'Local worker must explicitly enable ACME execution; queued jobs are inert by default'}
