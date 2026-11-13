"""Explicit operator-run local ACME rotation and verified TLS deployment.

Run only in the authorized APEX sandbox, after stopping the old 8443 demo.
No remote jobs, no arbitrary hosts, no automatic revocation.
"""
from __future__ import annotations
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from .acme_deploy import CERT, KEY
from .local_worker import DEFAULT_DIRECTORY, certificate_serial, verify_served_certificate

HOST = "service-01.demo.local"
STATE = Path("/tmp/apex-acme-recovery.json")


def run() -> int:
    if os.geteuid() != 0:
        print("Run with sudo; no sudoers policy changes required.", file=sys.stderr)
        return 1
    with socket.socket() as s:
        s.settimeout(2)
        if s.connect_ex(("127.0.0.1", 8443)) == 0:
            print("STOP: 8443 is occupied. Stop the old demo server first; will not kill processes.", file=sys.stderr)
            return 1
    try:
        before = certificate_serial(CERT)
        command = ["certbot", "certonly", "--standalone",
                   "--server", DEFAULT_DIRECTORY, "--preferred-challenges", "http",
                   "--cert-name", HOST, "-d", HOST, "--force-renewal",
                   "--non-interactive", "--agree-tos", "--register-unsafely-without-email"]
        print("Issuing replacement using pinned local Smallstep ACME CA...", flush=True)
        result = subprocess.run(command, timeout=240)
        if result.returncode:
            print("STOP: Certbot issuance failed; no revocation attempted.", file=sys.stderr)
            return 1
        after = certificate_serial(CERT)
        if before == after:
            print("STOP: Certificate serial did not change.", file=sys.stderr)
            return 1
        check = subprocess.run(["openssl", "x509", "-in", CERT, "-noout",
                                "-checkend", "3600", "-ext", "subjectAltName"],
                               capture_output=True, text=True, timeout=15)
        if check.returncode or "DNS:" + HOST not in check.stdout:
            print("STOP: New certificate SAN/validity failed.", file=sys.stderr)
            return 1
        if not Path(KEY).is_file():
            print("STOP: New private key missing.", file=sys.stderr)
            return 1
        print("Launching loopback TLS demo with new certificate...", flush=True)
        server = subprocess.Popen(["openssl", "s_server", "-accept", "127.0.0.1:8443",
                                   "-cert", CERT, "-key", KEY, "-www"],
                                  stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        verified = False
        for _ in range(12):
            if server.poll() is not None:
                break
            time.sleep(0.5)
            if verify_served_certificate(CERT):
                verified = True
                break
        if not verified:
            server.terminate()
            print("STOP: New certificate was not verified on live TLS. Old CA certificate NOT revoked.", file=sys.stderr)
            return 1
        state = {"old_serial": before, "new_serial": after, "server_pid": server.pid,
                 "deployed_and_verified": True, "old_ca_revoked": False}
        STATE.write_text(json.dumps(state, indent=2))
        print("SUCCESS: new ACME certificate deployed and served fingerprint verified.")
        print("Old serial:", before, "| New serial:", after)
        print("Old certificate NOT revoked; verify CA revocation separately before claiming full recovery.")
        print("Local process PID:", server.pid)
        return 0
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print("STOP: Local recovery failed:", type(exc).__name__, file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicit local sandbox ACME rotation + verified TLS deployment")
    parser.add_argument("--rotate-and-deploy", action="store_true", required=True)
    args = parser.parse_args()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
