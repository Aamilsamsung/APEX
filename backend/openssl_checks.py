"""Read-only OpenSSL verification of sandbox X.509 certificate files."""
from __future__ import annotations
import subprocess
from pathlib import Path
from . import core
from .chains import validate_bundle

def inspect_certificate(certificate_id: str) -> dict:
    with core.connect() as db:
        row=db.execute('SELECT path FROM certificates WHERE id=? AND active=1',(certificate_id,)).fetchone()
    if not row: raise ValueError('Active certificate not found')
    path=Path(row['path']).resolve()
    if not path.is_file() or path.suffix.lower() not in ('.pem','.crt','.cer'):
        raise ValueError('Certificate file missing or unsupported')
    # All command arguments are fixed or derived from the registered inventory.
    # No shell, network access, private keys, or arbitrary file paths from clients.
    ca_path=(core.CERTS/'sandbox-ca.pem').resolve()
    def run(args):
        try:
            result=subprocess.run(['openssl',*args],capture_output=True,text=True,
                                  timeout=8,check=False)
        except FileNotFoundError as exc:
            raise RuntimeError('OpenSSL CLI is not installed or not on PATH') from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError('OpenSSL command timed out') from exc
        return {'ok':result.returncode==0,
                'output':(result.stdout+'\n'+result.stderr).strip()[:4000]}
    details=run(['x509','-in',str(path),'-noout','-subject','-issuer','-dates',
                 '-serial','-fingerprint','-sha256','-text'])
    # Verify against the private sandbox CA, not the operating system trust store.
    core.ensure_ca()
    valid, error = validate_bundle(path.read_bytes(), ca_path.read_bytes())
    chain = {'ok': valid, 'output': error or 'Sandbox issuer path verified'}
    core.audit('openssl.certificate.inspected',
               {'certificate_id':certificate_id,'chain_valid':chain['ok']})
    return {'certificate_id':certificate_id,'details':details,
            'sandbox_ca_verification':chain}
