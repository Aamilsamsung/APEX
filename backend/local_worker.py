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



def certificate_serial(cert_path: str) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-serial"],
        capture_output=True, text=True, timeout=15, check=True)
    return result.stdout.strip()


def rotate_demo_certificate(directory: str) -> tuple[bool, str]:
    """Issue a fresh demo certificate; never claim CA revocation or deployment."""
    if directory != DEFAULT_DIRECTORY:
        return False, "ACME directory differs from the pinned private demo CA"
    cert = DEFAULT_CERT
    try:
        before = certificate_serial(cert)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False, "Cannot inspect existing certificate; worker needs scoped Certbot permissions"
    command = ["sudo", "-n", "certbot", "certonly", "--standalone",
               "--server", DEFAULT_DIRECTORY, "--preferred-challenges", "http",
               "--cert-name", "service-01.demo.local", "-d", "service-01.demo.local",
               "--force-renewal", "--non-interactive", "--agree-tos",
               "--register-unsafely-without-email"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=240)
        if result.returncode != 0:
            return False, "Certbot failed; inspect local Certbot logs and sudo permissions"
        after = certificate_serial(cert)
        if before == after:
            return False, "Certbot returned success but certificate serial did not change"
        verification = subprocess.run(
            ["openssl", "x509", "-in", cert, "-noout", "-checkend", "3600",
             "-ext", "subjectAltName"], capture_output=True, text=True, timeout=15)
        if verification.returncode or "DNS:service-01.demo.local" not in verification.stdout:
            return False, "Replacement certificate SAN or validity verification failed"
        return True, f"ACME reissued and verified; old serial {before}; new serial {after}; CA revocation and service deployment NOT performed"
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False, "ACME operation or verification failed locally"



def verify_served_certificate(cert_path: str, host: str = "127.0.0.1", port: int = 8443, *, ca_file: Path | None = None) -> bool:
    """Read-only comparison of local PEM and certificate served by loopback TLS."""
    import hashlib
    import socket
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    if host != "127.0.0.1" or not (1024 <= port <= 65535):
        raise ValueError("Only the local sandbox TLS endpoint is allowed")
    try:
        pem = Path(cert_path).read_bytes()
        expected = x509.load_pem_x509_certificate(pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_file is None:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.hostname_checks_common_name = False
            ctx.load_verify_locations(cafile=str(ca_file))
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="service-01.demo.local") as tls:
                der = tls.getpeercert(binary_form=True)
        served = x509.load_der_x509_certificate(der)
        matching = expected.fingerprint(hashes.SHA256()) == served.fingerprint(hashes.SHA256())
        print("Expected serial:", format(expected.serial_number, "X"))
        print("Served serial:  ", format(served.serial_number, "X"))
        print("TLS certificate fingerprint:", hashlib.sha256(der).hexdigest())
        print("PASS: served certificate matches local PEM" if matching else "FAIL: TLS endpoint is serving a different certificate")
        return matching
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"FAIL: local TLS verification unavailable ({type(exc).__name__})", file=sys.stderr)
        return False



def scan_local_demo_endpoints() -> list[dict]:
    """Read-only loopback TLS observations; never transmit keys or certificate PEM."""
    import socket
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    targets=((8443,"service-01.demo.local"),(8445,"weak.demo.local"),(8446,"service-01.demo.local"))
    observations=[]
    for port,expected in targets:
        row=dict(port=port,expected_hostname=expected,reachable=False,subject='',serial='',
                 key_bits=0,days_remaining=0,hostname_matches=False,error='')
        try:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname=False
            ctx.verify_mode=ssl.CERT_NONE
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
            with socket.create_connection(("127.0.0.1",port),timeout=4) as sock:
                with ctx.wrap_socket(sock,server_hostname=expected) as tls:
                    der=tls.getpeercert(binary_form=True)
            cert=x509.load_der_x509_certificate(der)
            try:
                sans=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans=[v.value for v in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
            from .chains import dns_matches
            row.update(reachable=True,subject=cert.subject.rfc4514_string()[:300],
                       serial=format(cert.serial_number,'X'),key_bits=getattr(cert.public_key(),'key_size',0),
                       days_remaining=int((cert.not_valid_after_utc-datetime.now(timezone.utc)).total_seconds()//86400),
                       hostname_matches=any(dns_matches(expected,name) for name in sans))
        except (OSError,ssl.SSLError,ValueError) as exc:
            row['error']=type(exc).__name__
        observations.append(row)
    return observations

def run_jobs(site: str, token: str, cert_path: str, once: bool = False, enable_acme: bool = False, directory: str = DEFAULT_DIRECTORY) -> int:
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
    print("APEX worker started (" + ("explicitly enabled demo ACME issuance" if enable_acme else "certificate inspection only") + ").",flush=True)
    last_scan=0.0
    while True:
        try:
            if time.monotonic()-last_scan>=30:
                observations=scan_local_demo_endpoints()
                call(site.rstrip('/')+'/api/worker/local-tls-report','POST',{'observations':observations})
                print('Local TLS scan reported: '+', '.join(str(o['port'])+(' OK' if o['reachable'] else ' unavailable') for o in observations),flush=True)
                last_scan=time.monotonic()
            jobs=call(base)
            for job in jobs:
                if job["status"]!="queued" or job["hostname"]!="service-01.demo.local" or (job["action"]!="inspect_certificate" and not (enable_acme and job["action"]=="acme_recovery")):
                    continue
                call(base+"/"+job["id"]+"/claim","POST",{})
                try:
                    if job["action"]=="acme_recovery":
                        ok, details = rotate_demo_certificate(directory)
                        call(base+"/"+job["id"]+"/complete","POST",{"ok":ok,"details":details})
                        print(f"Job {job['id']}: {'completed' if ok else 'failed'} — {details}",flush=True)
                        continue
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
    parser.add_argument("--verify-served", action="store_true", help="Read-only comparison against 127.0.0.1:8443 TLS certificate")
    parser.add_argument("--connect", action="store_true", help="Test authenticated connection to Render")
    parser.add_argument("--run", action="store_true", help="Poll approved inspection jobs (read-only)")
    parser.add_argument("--once", action="store_true", help="Poll once and exit")
    parser.add_argument("--enable-acme", action="store_true", help="Explicitly allow approved demo ACME reissuance; no CA revocation")
    parser.add_argument("--site", default=os.getenv("AEGIS_SITE_URL", "https://apex-aegis-pki.onrender.com"))
    parser.add_argument("--directory", default=os.getenv("AEGIS_ACME_DIRECTORY_URL", DEFAULT_DIRECTORY))
    parser.add_argument("--cert", default=DEFAULT_CERT)
    args = parser.parse_args()
    if args.verify_served:
        return 0 if verify_served_certificate(args.cert) else 1
    if args.run:
        return run_jobs(args.site, os.getenv("AEGIS_WORKER_TOKEN",""), args.cert, args.once, args.enable_acme, args.directory)
    if args.connect:
        return 0 if check_remote(args.site, os.getenv("AEGIS_WORKER_TOKEN", "")) else 1
    if not args.check:
        print("Remote worker integration is not configured yet. Run --check to verify the local PKI setup.")
        return 2
    return 0 if check_environment(args.directory, args.cert) else 1


if __name__ == "__main__":
    raise SystemExit(main())
