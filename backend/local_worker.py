"""APEX local PKI worker preflight. Read-only until remote job API is configured.

Run: python -m backend.local_worker --check
"""
from __future__ import annotations

import argparse
import time
import urllib.error
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

DEFAULT_DIRECTORY = "https://localhost:9000/acme/acme/directory"
DEFAULT_CERT = "/etc/letsencrypt/live/service-01.demo.local/fullchain.pem"


def check_environment(directory: str, cert_path: str) -> bool:
    checks = {}
    checks["certbot_installed"] = shutil.which("certbot") is not None
    try:
        with urllib.request.urlopen(directory, timeout=8, context=ssl.create_default_context()) as response:
            body = json.load(response)
        checks["private_acme_reachable"] = all(k in body for k in ("newNonce", "newAccount", "newOrder"))
    except Exception as exc:
        checks["private_acme_reachable"] = False
        print(f"ACME connectivity error: {type(exc).__name__}: {exc}", file=sys.stderr)
    try:
        checks["certificate_present"] = Path(cert_path).is_file()
    except PermissionError:
        checks["certificate_present"] = False
        print("Certbot certificate directory is protected. Run preflight with sudo or configure scoped access.", file=sys.stderr)
    if checks["certificate_present"]:
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-dates", "-issuer", "-ext", "subjectAltName"],
                capture_output=True, text=True, timeout=10, check=True
            )
            print(result.stdout.strip())
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            checks["certificate_readable"] = False
            print(f"Certificate inspection failed: {exc}", file=sys.stderr)
        else:
            checks["certificate_readable"] = True
    for name, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    return all(checks.values())


def check_remote(site: str, token: str) -> bool:
    if not site.startswith("https://") or not token:
        print("Set AEGIS_WORKER_TOKEN and use an HTTPS Render URL.", file=sys.stderr)
        return False
    url = site.rstrip("/") + "/api/worker/ping"
    request = urllib.request.Request(url, headers={"X-Aegis-Worker-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.load(response)
        print("Remote handshake:", data)
        return data.get("ok") is True
    except (urllib.error.URLError, ValueError) as exc:
        print(f"Remote handshake failed: {exc}", file=sys.stderr)
        return False



def run_jobs(site: str, token: str, cert_path: str, once: bool = False) -> int:
    if not site.startswith("https://") or not token:
        print("HTTPS site and AEGIS_WORKER_TOKEN required", file=sys.stderr)
        return 1
    base=site.rstrip("/") + "/api/worker/jobs"
    headers={"X-Aegis-Worker-Token":token}
    def call(url, method="GET", payload=None):
        data=json.dumps(payload).encode() if payload is not None else None
        h={**headers,**({"Content-Type":"application/json"} if data else {})}
        with urllib.request.urlopen(urllib.request.Request(url,data=data,headers=h,method=method),timeout=20) as response:
            return json.load(response)
    print("APEX worker started (certificate inspection only; no revocation or renewal).",flush=True)
    while True:
        try:
            jobs=call(base)
            for job in jobs:
                if job["status"]!="queued" or job["action"]!="inspect_certificate" or job["hostname"]!="service-01.demo.local":
                    continue
                call(base+"/"+job["id"]+"/claim","POST",{})
                try:
                    result=subprocess.run(["openssl","x509","-in",cert_path,"-noout","-serial","-dates","-ext","subjectAltName"],
                        capture_output=True,text=True,timeout=15,check=True)
                    details=result.stdout[:1800]
                    ok=True
                except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
                    details=f"Certificate inspection failed: {type(exc).__name__}"
                    ok=False
                call(base+"/"+job["id"]+"/complete","POST",{"ok":ok,"details":details})
                print(f"Job {job['id']}: {'completed' if ok else 'failed'}",flush=True)
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            print(f"Worker connection error: {exc}",file=sys.stderr,flush=True)
        if once: return 0
        time.sleep(10)


def main() -> int:
    parser = argparse.ArgumentParser(description="APEX local PKI worker preflight (read-only)")
    parser.add_argument("--check", action="store_true", help="Check local Smallstep, Certbot and certificate")
    parser.add_argument("--connect", action="store_true", help="Test authenticated connection to Render")
    parser.add_argument("--run", action="store_true", help="Poll approved inspection jobs (read-only)")
    parser.add_argument("--once", action="store_true", help="Poll once and exit")
    parser.add_argument("--site", default=os.getenv("AEGIS_SITE_URL", "https://apex-aegis-pki.onrender.com"))
    parser.add_argument("--directory", default=os.getenv("AEGIS_ACME_DIRECTORY_URL", DEFAULT_DIRECTORY))
    parser.add_argument("--cert", default=DEFAULT_CERT)
    args = parser.parse_args()
    if args.run:
        return run_jobs(args.site, os.getenv("AEGIS_WORKER_TOKEN",""), args.cert, args.once)
    if args.connect:
        return 0 if check_remote(args.site, os.getenv("AEGIS_WORKER_TOKEN", "")) else 1
    if not args.check:
        print("Remote worker integration is not configured yet. Run --check to verify the local PKI setup.")
        return 2
    return 0 if check_environment(args.directory, args.cert) else 1


if __name__ == "__main__":
    raise SystemExit(main())
