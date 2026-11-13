"""APEX local PKI worker preflight. Read-only until remote job API is configured.

Run: python -m backend.local_worker --check
"""
from __future__ import annotations

import argparse
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


def main() -> int:
    parser = argparse.ArgumentParser(description="APEX local PKI worker preflight (read-only)")
    parser.add_argument("--check", action="store_true", help="Check local Smallstep, Certbot and certificate")
    parser.add_argument("--directory", default=os.getenv("AEGIS_ACME_DIRECTORY_URL", DEFAULT_DIRECTORY))
    parser.add_argument("--cert", default=DEFAULT_CERT)
    args = parser.parse_args()
    if not args.check:
        print("Remote worker integration is not configured yet. Run --check to verify the local PKI setup.")
        return 2
    return 0 if check_environment(args.directory, args.cert) else 1


if __name__ == "__main__":
    raise SystemExit(main())
