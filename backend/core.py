"""AEGIS PKI: local, authorized certificate security sandbox."""
from __future__ import annotations
import json, os, sqlite3, ssl, socket, threading, uuid, urllib.request, urllib.error, fnmatch, hashlib, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv('AEGIS_DATA_DIR', str(ROOT / 'data')))
CERTS = DATA / 'certificates'
DB = DATA / 'aegis.db'
LOCK = threading.RLock()
_CA_CACHE = {}
UTC = timezone.utc

def now(): return datetime.now(UTC)
def timestamp(): return now().isoformat()
def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    c=sqlite3.connect(DB,timeout=15)
    c.row_factory=sqlite3.Row
    return c

def init_db():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY, hostname TEXT NOT NULL, path TEXT NOT NULL, key_path TEXT NOT NULL, compromised INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, source TEXT NOT NULL DEFAULT 'sandbox-file');
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, certificate_id TEXT NOT NULL, code TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open');
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, certificate_id TEXT NOT NULL, type TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, approved_at TEXT, resolved_at TEXT, error TEXT);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS revoked_serials(serial TEXT PRIMARY KEY,revoked_at TEXT NOT NULL,reason TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_chain(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ct_feed(id TEXT PRIMARY KEY, hostname TEXT NOT NULL, issuer TEXT NOT NULL, authorized INTEGER NOT NULL DEFAULT 0);
        ''')

def audit(action,details):
    with connect() as c:
        stamp=timestamp(); payload=json.dumps(details,sort_keys=True)
        c.execute('INSERT INTO audit(timestamp,action,details) VALUES (?,?,?)',(stamp,action,payload))
        previous=c.execute('SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1').fetchone()
        prev=previous['entry_hash'] if previous else 'GENESIS'
        digest=hashlib.sha256(json.dumps([stamp,action,payload,prev],separators=(',',':')).encode()).hexdigest()
        c.execute('INSERT INTO audit_chain(timestamp,action,details,prev_hash,entry_hash) VALUES (?,?,?,?,?)',(stamp,action,payload,prev,digest))

def verify_audit_chain():
    prev='GENESIS'
    with connect() as c:
        for row in c.execute('SELECT * FROM audit_chain ORDER BY id'):
            expected=hashlib.sha256(json.dumps([row['timestamp'],row['action'],row['details'],prev],separators=(',',':')).encode()).hexdigest()
            if row['prev_hash']!=prev or row['entry_hash']!=expected: return {'valid':False,'failed_at':row['id']}
            prev=row['entry_hash']
        count=c.execute('SELECT COUNT(*) FROM audit_chain').fetchone()[0]
    return {'valid':True,'entries':count,'last_hash':prev}


def ensure_ca():
    CERTS.mkdir(parents=True, exist_ok=True)
    certfile, keyfile = CERTS / 'sandbox-ca.pem', CERTS / 'sandbox-ca.key'
    cache_key=str(certfile)
    if cache_key in _CA_CACHE: return _CA_CACHE[cache_key]
    if certfile.exists() and keyfile.exists():
        result=(x509.load_pem_x509_certificate(certfile.read_bytes()), serialization.load_pem_private_key(keyfile.read_bytes(), password=None))
        _CA_CACHE[cache_key]=result
        return result
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'AEGIS Sandbox Root CA')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now()-timedelta(days=1))
            .not_valid_after(now()+timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True,path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,
                 data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
                 encipher_only=False,decipher_only=False),critical=True)
            .sign(key,hashes.SHA256()))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    try: os.chmod(keyfile,0o600)
    except OSError: pass
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _CA_CACHE[str(certfile)]=(cert,key)
    return cert,key

def generate_cert(hostname, days=365, bits=2048, mismatch=False, expired=False):
    CERTS.mkdir(parents=True,exist_ok=True)
    key=rsa.generate_private_key(public_exponent=65537,key_size=bits)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)])
    san=hostname if not mismatch else 'different.demo.local'
    start=now()-timedelta(days=30 if expired else 1)
    end=now()-timedelta(days=1) if expired else now()+timedelta(days=days)
    ca_cert, ca_key = ensure_ca()
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(ca_cert.subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(start).not_valid_after(end)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),critical=False)
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .sign(ca_key,hashes.SHA256()))
    uid=uuid.uuid4().hex[:12]
    certpath=CERTS/f'{uid}.pem'; keypath=CERTS/f'{uid}.key'
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    try: os.chmod(keypath,0o600)
    except OSError: pass
    return uid,str(certpath),str(keypath)


def import_public_certificate(pem_text, hostname):
    """Import only a public X.509 certificate into the isolated sandbox inventory."""
    if not isinstance(pem_text,str) or len(pem_text)>65536:
        raise ValueError('Certificate must be public PEM text under 64 KB')
    if 'PRIVATE KEY' in pem_text or 'BEGIN CERTIFICATE' not in pem_text:
        raise ValueError('Only a public PEM certificate is accepted; never upload private keys')
    if not isinstance(hostname,str) or not (1<=len(hostname)<=253) or not all(
        part and len(part)<=63 and all(ch.isalnum() or ch=='-' for ch in part) for part in hostname.split('.')
    ):
        raise ValueError('Enter a valid DNS hostname')
    try:
        cert=x509.load_pem_x509_certificate(pem_text.encode('ascii'))
    except (ValueError,UnicodeError) as exc:
        raise ValueError('Invalid X.509 PEM certificate') from exc
    init_db()
    uid=uuid.uuid4().hex[:12]
    CERTS.mkdir(parents=True,exist_ok=True)
    path=CERTS/f'{uid}.pem'
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    with connect() as db:
        db.execute('INSERT INTO certificates(id,hostname,path,key_path,source) VALUES(?,?,?,?,?)',
                   (uid,hostname,str(path),'','uploaded-public-cert'))
    audit('certificate.imported',{'id':uid,'hostname':hostname,'source':'public PEM upload','fingerprint':cert.fingerprint(hashes.SHA256()).hex()})
    scan()
    return {'certificate_id':uid,'hostname':hostname,'source':'uploaded-public-cert'}

def seed():
    init_db()
    with LOCK:
        with connect() as c:
            if c.execute('SELECT COUNT(*) FROM certificates').fetchone()[0]: return False
            for i in range(30):
                hostname=f'service-{i+1:02d}.demo.local'
                opts={}
                if i in (1,5,12): opts['days']=5
                if i in (2,14): opts['bits']=1024
                if i in (3,16): opts['mismatch']=True
                if i in (4,19): opts['expired']=True
                uid,certpath,keypath=generate_cert(hostname,**opts)
                c.execute('INSERT INTO certificates(id,hostname,path,key_path) VALUES(?,?,?,?)',(uid,hostname,certpath,keypath))
        seed_mock_ct()
        audit('sandbox.seed',{'count':30,'note':'All certificates are local, CA-signed sandbox fixtures; no external targets scanned'})
    return True

def describe(row):
    cert=x509.load_pem_x509_certificate(Path(row['path']).read_bytes())
    key=cert.public_key()
    try: sans=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: sans=[]
    ca_cert,_ = ensure_ca()
    try:
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        chain_valid = cert.issuer == ca_cert.subject
    except Exception: chain_valid = False
    return {'chain_valid':chain_valid,'id':row['id'],'hostname':row['hostname'],'subject':cert.subject.rfc4514_string(),
            'issuer':cert.issuer.rfc4514_string(),'sans':sans,
            'expires_at':cert.not_valid_after_utc.isoformat(),'days_remaining':int((cert.not_valid_after_utc-now()).total_seconds()/86400),
            'key_type':'RSA' if isinstance(key,rsa.RSAPublicKey) else 'EC' if isinstance(key,ec.EllipticCurvePublicKey) else 'Other',
            'key_bits':key.key_size if hasattr(key,'key_size') else None,
            'signature':cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'unknown',
            'self_signed':cert.issuer==cert.subject, 'validity_days':(cert.not_valid_after_utc-cert.not_valid_before_utc).days,
            'fingerprint':cert.fingerprint(hashes.SHA256()).hex()[:20],
            'compromised':bool(row['compromised']),'revoked':bool(row['revoked']),'active':bool(row['active']),
            'source':row['source'],'serial':format(cert.serial_number,'x')}

def inventory():
    with connect() as c: rows=c.execute('SELECT * FROM certificates WHERE active=1 ORDER BY hostname').fetchall()
    return [describe(r) for r in rows]

def assess(cert):
    results=[]
    def add(code,severity,msg): results.append({'code':code,'severity':severity,'message':msg})
    days=cert['days_remaining']
    if days < 0: add('EXPIRED','critical','Certificate has expired')
    elif days <= 7: add('EXPIRING_7D','high',f'Certificate expires in {days} days')
    elif days <= 14: add('EXPIRING_14D','medium',f'Certificate expires in {days} days')
    elif days <= 30: add('EXPIRING_30D','low',f'Certificate expires in {days} days')
    if cert['key_type']=='RSA' and cert['key_bits']<2048: add('WEAK_RSA','critical',f"RSA-{cert['key_bits']} is below 2048 bits")
    if cert['signature'].lower() in ('sha1','md5'): add('WEAK_SIGNATURE','critical','Weak certificate signature hash')
    if not any(name==cert['hostname'] or (name.startswith('*.') and cert['hostname'].endswith(name[1:]) and cert['hostname'].count('.')==name.count('.')) for name in cert['sans']): add('HOSTNAME_MISMATCH','high','Expected hostname is absent from SANs')
    if cert.get('chain_valid') is False: add('INVALID_CHAIN','critical','Certificate signature does not verify against sandbox CA')
    if cert.get('self_signed'): add('UNEXPECTED_SELF_SIGNED','critical','Leaf certificate is self-signed instead of sandbox CA-issued')
    if cert.get('validity_days',0)>398: add('LONG_VALIDITY','medium','Certificate validity exceeds sandbox policy of 398 days')
    wildcards=[name for name in cert['sans'] if name.startswith('*.')]
    if wildcards:
        # A wildcard must match exactly one DNS label, not arbitrary subdomains.
        valid_wildcard=any(
            cert['hostname'].endswith(name[1:]) and
            cert['hostname'].count('.')==name.count('.')
            for name in wildcards
        )
        if not valid_wildcard:
            add('WILDCARD_MISUSE','high','Wildcard SAN does not cover exactly one label of the registered hostname')
    if cert['compromised']: add('KEY_COMPROMISE','critical','Sandbox incident simulator marked this private key compromised')
    if cert['revoked']: add('REVOKED','critical','Certificate is marked revoked by sandbox authority')
    # Trust validation is handled separately using the local sandbox CA.
    return results

def scan():
    with LOCK:
        certs=inventory()
        with connect() as c:
            c.execute('DELETE FROM findings')
            for cert in certs:
                for finding in assess(cert):
                    fid=f"{cert['id']}:{finding['code']}"
                    c.execute('INSERT INTO findings(id,certificate_id,code,severity,message) VALUES(?,?,?,?,?)',
                              (fid,cert['id'],finding['code'],finding['severity'],finding['message']))
        result=summary()
        audit('scan.completed',{'certificates':len(certs),'scope':'registered local sandbox certificate files','health':result['health']})
    return result


def health_history(limit=60):
    """Historical scores from actual completed scans, never synthesized."""
    with connect() as db:
        rows=db.execute("SELECT timestamp,details FROM audit WHERE action='scan.completed' ORDER BY id DESC LIMIT ?",(max(1,min(int(limit),200)),)).fetchall()
    history=[]
    for row in reversed(rows):
        try:
            data=json.loads(row['details'])
            if isinstance(data.get('health'),int):
                history.append({'timestamp':row['timestamp'],'health':data['health']})
        except (ValueError,TypeError):
            continue
    return history


def findings():
    with connect() as c: return [dict(r) for r in c.execute('SELECT * FROM findings ORDER BY CASE severity WHEN "critical" THEN 0 WHEN "high" THEN 1 WHEN "medium" THEN 2 ELSE 3 END,code')]

def summary():
    certs=inventory(); fs=findings()
    penalties={'critical':30,'high':15,'medium':7,'low':3}
    # Per-certificate cap avoids double counting and makes score comparable across inventory sizes.
    per_cert={cert['id']:0 for cert in certs}
    for f in fs: per_cert[f['certificate_id']]=min(100,per_cert.get(f['certificate_id'],0)+penalties[f['severity']])
    health=round(100-sum(per_cert.values())/len(certs)) if certs else 100
    return {'health':health,'total':len(certs),'healthy':sum(1 for v in per_cert.values() if v==0),
            'at_risk':sum(1 for v in per_cert.values() if v>0),
            'critical':sum(1 for f in fs if f['severity']=='critical'),
            'high':sum(1 for f in fs if f['severity']=='high'),
            'warnings':sum(1 for f in fs if f['severity'] in ('medium','low')),
            'score_method':'100 minus mean per-certificate risk penalty (critical 30, high 15, medium 7, low 3; capped at 100 per certificate)',
            'scope':'Local sandbox certificate files plus optional registered loopback TLS endpoint'}

def simulate_compromise(cert_id):
    with LOCK:
        with connect() as c:
            row=c.execute('SELECT * FROM certificates WHERE id=? AND active=1',(cert_id,)).fetchone()
            if not row: raise ValueError('Active certificate not found')
            if row['source']=='uploaded-public-cert': raise ValueError('Imported certificates are scan-only; sandbox remediation requires a managed sandbox key')
            pending=c.execute('SELECT id FROM incidents WHERE certificate_id=? AND status IN ("pending_approval","approved","executing")',(cert_id,)).fetchone()
            if pending: raise ValueError('An incident is already open for this certificate')
            incident_id=uuid.uuid4().hex[:12]
            c.execute('UPDATE certificates SET compromised=1 WHERE id=?',(cert_id,))
            c.execute('INSERT INTO incidents(id,certificate_id,type,status,created_at) VALUES(?,?,?,?,?)',(incident_id,cert_id,'SIMULATED_KEY_COMPROMISE','pending_approval',timestamp()))
        audit('incident.simulated',{'incident_id':incident_id,'certificate_id':cert_id,'evidence':'explicit sandbox simulation flag; not inferred from TLS'})
        scan()
    return incident_id

def incidents():
    with connect() as c: return [dict(r) for r in c.execute('SELECT * FROM incidents ORDER BY created_at DESC')]

def reject(incident_id):
    with LOCK:
        with connect() as c:
            cur=c.execute('UPDATE incidents SET status="rejected" WHERE id=? AND status="pending_approval"',(incident_id,))
            if not cur.rowcount: raise ValueError('Incident not pending approval')
        audit('remediation.rejected',{'incident_id':incident_id})

def approve_and_remediate(incident_id,actor):
    if not actor or not actor.strip(): raise ValueError('Approver name required')
    with LOCK:
        with connect() as c:
            incident=c.execute('SELECT * FROM incidents WHERE id=? AND status="pending_approval"',(incident_id,)).fetchone()
            if not incident: raise ValueError('Incident not pending approval')
            row=c.execute('SELECT * FROM certificates WHERE id=? AND active=1',(incident['certificate_id'],)).fetchone()
            if not row: raise ValueError('Affected certificate no longer active')
            c.execute('UPDATE incidents SET status="executing",approved_at=? WHERE id=?',(timestamp(),incident_id))
        audit('remediation.approved',{'incident_id':incident_id,'approver':actor})
        try:
            # This is an isolated sandbox workflow, not a production CA or ACME integration.
            old=describe(row)
            new_id,path,key_path=generate_cert(old['hostname'],days=365,bits=2048)
            new_cert=x509.load_pem_x509_certificate(Path(path).read_bytes())
            assert new_cert.not_valid_after_utc>now()
            assert new_cert.public_key().key_size>=2048
            assert old['hostname'] in new_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            audit('remediation.key_generated',{'incident_id':incident_id,'new_certificate_id':new_id,'key_bits':2048})
            audit('remediation.certificate_issued',{'incident_id':incident_id,'new_certificate_id':new_id,'issuer':'AEGIS Sandbox Root CA'})
            with connect() as c:
                c.execute('INSERT INTO revoked_serials(serial,revoked_at,reason) VALUES(?,?,?)',(old['serial'],timestamp(),'keyCompromise'))
                c.execute('UPDATE certificates SET revoked=1,active=0 WHERE id=?',(row['id'],))
                c.execute('INSERT INTO certificates(id,hostname,path,key_path,source) VALUES(?,?,?,?,?)',(new_id,old['hostname'],path,key_path,'sandbox-reissued'))
                c.execute('UPDATE incidents SET status="resolved",resolved_at=? WHERE id=?',(timestamp(),incident_id))
            audit('remediation.revoked',{'incident_id':incident_id,'old_serial':old['serial'],'mechanism':'sandbox revocation registry'})
            # A live endpoint is optional; when present, verify the actual TLS-served certificate.
            live_verification={'status':'not_running','detail':'No local TLS endpoint was registered for this certificate'}
            if old['hostname']=='service-01.demo.local':
                try:
                    for attempt in range(20):
                        try:
                            served=scan_tls_endpoint('127.0.0.1',8443,old['hostname'])
                            if served['serial']==format(new_cert.serial_number,'x') and served['chain_valid'] and served['hostname_valid'] and not served['revoked']:
                                live_verification={'status':'verified','endpoint':'127.0.0.1:8443','serial':served['serial']}
                                break
                        except (OSError,ssl.SSLError):
                            # The demo TLS server may briefly close its socket while
                            # loading the new certificate; retry through that handoff.
                            pass
                        time.sleep(.2)
                    else: live_verification={'status':'failed','detail':'Running TLS endpoint did not serve replacement certificate'}
                except Exception as exc: live_verification={'status':'failed','detail':str(exc)}
            audit('remediation.deployment_verified',{'incident_id':incident_id,**live_verification})
            from .notifications import notify
            notification=notify(incident_id,old['hostname'],'resolved',live_verification)
            audit('remediation.completed',{'incident_id':incident_id,'old_certificate':row['id'],'new_certificate':new_id,
                  'steps':['sandbox CA revocation registry updated','fresh private key generated','CA-signed sandbox certificate issued','registered endpoint certificate pointer updated','replacement certificate validated'],
                  'limitation':'Local CA issuance (not ACME); live endpoint verification and webhook delivery recorded separately'})
            audit('remediation.notification_result',{'incident_id':incident_id,**notification})
            scan()
            return {'new_certificate_id':new_id,'incident_id':incident_id,'status':'resolved','tls_verification':live_verification,'notification':notification,
                    'remediation_steps':remediation_steps(incident_id)}
        except Exception as exc:
            with connect() as c: c.execute('UPDATE incidents SET status="failed",error=? WHERE id=?',(str(exc),incident_id))
            audit('remediation.failed',{'incident_id':incident_id,'error':str(exc)})
            raise

def remediation_steps(incident_id):
    """Explain only actions supported by the recorded sandbox audit events."""
    with connect() as c:
        incident=c.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not incident: raise ValueError('Incident not found')
        entries=[dict(r) for r in c.execute('SELECT action, timestamp, details FROM audit ORDER BY id')]
    steps=[]
    comparison = {}
    deployment = None
    def step(title,detail,at): steps.append({'title':title,'detail':detail,'timestamp':at})
    for entry in entries:
        data=json.loads(entry['details'])
        if data.get('incident_id')!=incident_id: continue
        action=entry['action']; at=entry['timestamp']
        if action=='incident.simulated': step('Compromise detected (simulation)','A controlled incident flag was set. No real private-key theft was detected.',at)
        elif action=='remediation.approved': step('Human approval recorded',f"Operator {data.get('approver','unknown')} authorized the sandbox recovery.",at)
        elif action=='remediation.rejected': step('Remediation rejected','No certificate rotation was authorized.',at)
        elif action=='remediation.completed':
            with connect() as c:
                for label, key in (('before', 'old_certificate'), ('after', 'new_certificate')):
                    row = c.execute('SELECT * FROM certificates WHERE id=?', (data.get(key),)).fetchone()
                    if row and Path(row['path']).is_file():
                        cert = describe(row)
                        comparison[label] = {field: cert[field] for field in (
                            'hostname', 'expires_at', 'key_type', 'key_bits', 'fingerprint', 'serial'
                        )}
            step('Old certificate revoked in sandbox registry','The previous certificate serial was added to the local revocation database. This is not OCSP/CRL publication.',at)
            step('Fresh private key generated','A new RSA-2048 private key was created locally.',at)
            step('Replacement certificate issued','The local sandbox CA signed a replacement certificate with the original hostname.',at)
            step('Active certificate updated','The active inventory pointer was changed. The optional demo TLS server reloads on its next request.',at)
            step('Certificate properties verified','The replacement was checked for expiry, key strength and matching SAN; this is not proof of live TLS redeployment.',at)
        elif action=='remediation.deployment_verified':
            deployment = {**data, 'timestamp': at}
            step('Live TLS deployment check', 'Status: '+data['status']+'. '+(data.get('detail') or ('Verified endpoint '+data.get('endpoint',''))),at)
        elif action in ('notification.delivery','remediation.notification_result'):
            # Both events can describe the same delivery attempt; show it once.
            if action=='notification.delivery':
                status=data.get('status','unknown')
                if status=='delivered':
                    step('Owner notification delivered','Configured webhook confirmed successful delivery.',at)
                elif status=='not_configured':
                    step('Owner notification not configured','No webhook URL is configured; the delivery attempt was recorded in the audit log.',at)
                else:
                    step('Owner notification failed','Webhook delivery failed or was rejected; see the audit log for details.',at)
        elif action=='notification.mocked':
            step('Owner notification simulated','A local notification record was written; no external message was sent.',at)
        elif action=='remediation.local_acme_approved':
            step('Local ACME recovery approved','Operator authorized the allowlisted local ACME worker job; issuance is not yet confirmed.',at)
        elif action=='worker.job.completed' and data.get('action')=='acme_recovery':
            if data.get('ok'):
                step('ACME certificate issued locally','Local worker reported successful reissuance and SAN verification. CA revocation and live TLS redeployment remain unverified.',at)
            else:
                step('Local ACME recovery failed','Local worker reported a failed ACME job. Inspect worker audit evidence.',at)
        elif action=='remediation.failed': step('Remediation failed',str(data.get('error','Unknown error')),at)
    return {'incident_id':incident_id,'status':incident['status'],'steps':steps,'comparison':comparison,'deployment':deployment}

def logs(limit=100):
    with connect() as c:
        rows=c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT ?',(min(max(limit,1),500),)).fetchall()
        return [dict(r) for r in rows]

def explain_deterministically():
    fs=findings()
    explanations={
        'EXPIRED':'Renew immediately to restore certificate validity.',
        'EXPIRING_7D':'Schedule replacement urgently to avoid a service outage.',
        'EXPIRING_14D':'Plan renewal before the expiration window closes.',
        'EXPIRING_30D':'Track renewal in the upcoming maintenance cycle.',
        'WEAK_RSA':'Rotate to a new key of at least 2048 bits.',
        'WEAK_SIGNATURE':'Reissue with a modern signature algorithm.',
        'HOSTNAME_MISMATCH':'Reissue with the correct DNS name in SAN.',
        'KEY_COMPROMISE':'Seek approval to revoke, rotate key, reissue and verify.',
        'REVOKED':'Replace this certificate before using the endpoint.',
        'INVALID_CHAIN':'Verify the certificate issuer and chain before deployment.'}
    return {'mode':'deterministic-fallback','note':'Rule-based explanations; no LLM was used.',
            'recommendations':[{'finding_id':f['id'],'severity':f['severity'],'priority':i+1,'explanation':explanations.get(f['code'],'Review the finding.')} for i,f in enumerate(fs[:15])]}


def verify_revocation(serial):
    with connect() as c:
        return c.execute('SELECT 1 FROM revoked_serials WHERE serial=?',(serial,)).fetchone() is not None

def scan_tls_endpoint(host='127.0.0.1', port=8443, expected_hostname=None):
    """Read a registered local TLS server; deliberately restrict to loopback."""
    if host not in ('127.0.0.1','localhost','::1'):
        raise ValueError('Only authorized loopback sandbox endpoints are supported')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False
    context.verify_mode=ssl.CERT_NONE  # verify separately against the sandbox CA
    with socket.create_connection((host,port),timeout=3) as sock:
        with context.wrap_socket(sock,server_hostname=expected_hostname or 'localhost') as tls:
            der=tls.getpeercert(binary_form=True)
    cert=x509.load_der_x509_certificate(der)
    ca,_=ensure_ca()
    try:
        ca.public_key().verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
        trusted=cert.issuer==ca.subject
    except Exception: trusted=False
    sans=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    return {'endpoint':f'{host}:{port}','fingerprint':cert.fingerprint(hashes.SHA256()).hex(),
            'serial':format(cert.serial_number,'x'),'chain_valid':trusted,
            'hostname_valid':any(fnmatch.fnmatchcase(expected_hostname or '',san) for san in sans),
            'expires_at':cert.not_valid_after_utc.isoformat(),
            'revoked':verify_revocation(format(cert.serial_number,'x'))}

def explain_with_llm():
    """Explain and rank ONLY deterministic findings. LLM never creates findings."""
    fs=findings()[:15]
    fallback=explain_deterministically()
    if not fs:
        return {'mode':'deterministic-fallback','recommendations':[],
                'note':'No rule-generated findings; nothing for the LLM to report.'}
    key=os.environ.get('GROQ_API_KEY','').strip()
    if not key: return fallback
    allowed={f['id']:f for f in fs}
    prompt=json.dumps([{'id':f['id'],'code':f['code'],'severity':f['severity'],
                        'message':f['message']} for f in fs])
    request={'model':os.environ.get('GROQ_MODEL','openai/gpt-oss-20b'),
       'temperature':0,'response_format':{'type':'json_object'},
       'messages':[{'role':'system','content':(
           'You are a PKI risk analyst. Rank ONLY the supplied verified findings. '
           'Return JSON object {"recommendations":[{"finding_id":"exact supplied ID",'
           '"priority":1,"explanation":"plain-language explanation tied to supplied evidence"}]}. '
           'Priority 1 is most urgent; use unique integer ranks. Do not add findings, '
           'change severities, invent evidence, or include credentials.')},
                   {'role':'user','content':prompt}]}
    try:
        req=urllib.request.Request('https://api.groq.com/openai/v1/chat/completions',
            data=json.dumps(request).encode(),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=8) as response:
            body=json.load(response)
        parsed=json.loads(body['choices'][0]['message']['content'])
        items=parsed.get('recommendations',[])
        if not isinstance(items,list): raise ValueError('Recommendations must be a list')
        recommendations=[]; seen=set(); ranks=set()
        for item in items:
            if not isinstance(item,dict): continue
            fid=item.get('finding_id'); explanation=item.get('explanation','')
            priority=item.get('priority')
            if fid not in allowed or fid in seen or not isinstance(explanation,str) or not (5<=len(explanation)<=500):
                continue
            if isinstance(priority,bool) or not isinstance(priority,int) or priority<1 or priority>len(fs) or priority in ranks:
                continue
            recommendations.append({'finding_id':fid,'severity':allowed[fid]['severity'],
                                    'priority':priority,'explanation':explanation})
            seen.add(fid); ranks.add(priority)
        if len(recommendations)!=len(fs) or set(ranks)!=set(range(1,len(fs)+1)):
            raise ValueError('LLM ranking incomplete, invalid or ungrounded')
        recommendations.sort(key=lambda r:r['priority'])
        return {'mode':'groq-llm','recommendations':recommendations,
                'note':'Every recommendation maps to a rule-generated finding; LLM priority is advisory.'}
    except Exception as exc:
        audit('llm.fallback',{'error_type':type(exc).__name__})
        return fallback


def seed_mock_ct():
    """Local CT replay: known entry and unauthorized issuance event; no real CT network traffic."""
    with connect() as c:
        if not c.execute('SELECT 1 FROM ct_feed LIMIT 1').fetchone():
            c.execute('INSERT INTO ct_feed(id,hostname,issuer,authorized) VALUES(?,?,?,?)',('ct-known','service-01.demo.local','AEGIS Sandbox Root CA',1))
            c.execute('INSERT INTO ct_feed(id,hostname,issuer,authorized) VALUES(?,?,?,?)',('ct-rogue','rogue.demo.local','Unrecognized Test CA',0))

def ct_monitor():
    seed_mock_ct()
    with connect() as c:
        registered={r['hostname'] for r in c.execute('SELECT hostname FROM certificates WHERE active=1')}
        rows=[dict(r) for r in c.execute('SELECT * FROM ct_feed')]
    return [{'id':r['id'],'hostname':r['hostname'],'issuer':r['issuer'], 'status': 'suspected_rogue' if not r['authorized'] or r['hostname'] not in registered else 'known', 'source':'mock CT replay'} for r in rows]

def scan_registered_endpoint():
    """Scan only a fixed, authorized local endpoint; never an arbitrary remote target."""
    result=scan_tls_endpoint('127.0.0.1',8443,'service-01.demo.local')
    audit('endpoint.scanned',{'endpoint':result['endpoint'],'serial':result['serial'],'chain_valid':result['chain_valid']})
    return result
