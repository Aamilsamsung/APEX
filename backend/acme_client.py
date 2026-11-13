"""Optional operator-run ACME issuance against a private Smallstep step-ca server.

This is a standalone integration, not an unauthenticated web endpoint.
Requires certbot, an accessible private ACME directory, and a resolvable
authorized sandbox hostname whose HTTP-01 challenge reaches this machine.
"""
from __future__ import annotations
import argparse, os, subprocess, urllib.parse
from pathlib import Path

def issue_via_acme(hostname: str, directory_url: str, output_dir: str):
    parsed=urllib.parse.urlsplit(directory_url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Private ACME directory must use HTTPS')
    if not hostname.endswith('.demo.local') or len(hostname)>253:
        raise ValueError('Only authorized .demo.local sandbox names are accepted')
    if not all(part and all(ch.isalnum() or ch=='-' for ch in part) for part in hostname.split('.')):
        raise ValueError('Invalid hostname')
    root=Path(output_dir).resolve()
    root.mkdir(parents=True,exist_ok=True)
    command=['certbot','certonly','--standalone','--non-interactive','--agree-tos',
             '--register-unsafely-without-email','--preferred-challenges','http',
             '--server',directory_url,'--domain',hostname,
             '--config-dir',str(root/'config'),'--work-dir',str(root/'work'),
             '--logs-dir',str(root/'logs')]
    # Certbot validates the ACME server's TLS certificate using system trust.
    # Trust the private CA at the OS level before invoking this helper.
    result=subprocess.run(command,capture_output=True,text=True,timeout=180,check=False)
    return {'ok':result.returncode==0,'exit_code':result.returncode,
            'message':'ACME issuance completed' if result.returncode==0 else
                      'ACME issuance failed; inspect private certbot logs'}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--hostname',required=True)
    parser.add_argument('--directory',default=os.environ.get('AEGIS_ACME_DIRECTORY_URL',''))
    parser.add_argument('--output-dir',default='data/acme')
    args=parser.parse_args()
    if not args.directory: parser.error('Set --directory or AEGIS_ACME_DIRECTORY_URL')
    print(issue_via_acme(args.hostname,args.directory,args.output_dir))
