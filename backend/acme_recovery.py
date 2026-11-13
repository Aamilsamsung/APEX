"""Operator-approved recovery for the pinned local Smallstep demonstration."""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .acme_deploy import CERT, KEY
from .local_worker import DEFAULT_DIRECTORY, verify_served_certificate

HOST = "service-01.demo.local"
LIVE = Path(CERT).parent


def run(root: Path, approve_revocation: bool) -> int:
    if os.geteuid() != 0:
        print("Run from the authorized local sandbox with Certbot permissions.", file=sys.stderr)
        return 1
    with socket.socket() as sock:
        sock.settimeout(2)
        if sock.connect_ex(("127.0.0.1", 8443)) == 0:
            print("Port 8443 is occupied. Stop the previous sandbox TLS demo first.", file=sys.stderr)
            return 1
    try:
        # Use the existing archive paths so Certbot's rotation cannot change
        # the identity of the certificate and key later submitted to revokeCert.
        old_leaf = (LIVE / "cert.pem").resolve(strict=True)
        old_key = Path(KEY).resolve(strict=True)
        before = x509.load_pem_x509_certificate(old_leaf.read_bytes())
        subprocess.run(["openssl", "verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
                        "-trusted", str(root), "-untrusted", str(LIVE / "chain.pem"),
                        "-verify_hostname", HOST, str(old_leaf)], check=True, timeout=15,
                       capture_output=True)
        subprocess.run(["certbot", "certonly", "--standalone", "--server", DEFAULT_DIRECTORY,
                        "--preferred-challenges", "http", "--cert-name", HOST, "-d", HOST,
                        "--force-renewal", "--new-key", "--non-interactive", "--agree-tos",
                        "--register-unsafely-without-email"], check=True, timeout=240)
        after = x509.load_pem_x509_certificate((LIVE / "cert.pem").read_bytes())
        before_key = before.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        after_key = after.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if before.serial_number == after.serial_number or before_key == after_key:
            raise ValueError("Certificate or key did not rotate")

        server = subprocess.Popen(["openssl", "s_server", "-accept", "127.0.0.1:8443",
                                   "-cert", str(LIVE / "cert.pem"), "-cert_chain", str(LIVE / "chain.pem"),
                                   "-key", KEY, "-www"], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        verified = False
        try:
            for _ in range(12):
                if server.poll() is not None:
                    break
                time.sleep(0.5)
                if verify_served_certificate(CERT, ca_file=root):
                    verified = True
                    break
        finally:
            if not verified and server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
        if not verified:
            raise ValueError("Replacement did not pass the trusted loopback TLS handshake")
        print(f"Verified replacement serial {after.serial_number:X} on loopback TLS, PID {server.pid}.")
        if not approve_revocation:
            print("Old certificate remains active at the CA. Revocation requires explicit approval.")
            return 0

        # Verify service first to avoid revoking the only working certificate.
        subprocess.run(["certbot", "revoke", "--server", DEFAULT_DIRECTORY,
                        "--cert-path", str(old_leaf), "--key-path", str(old_key),
                        "--reason", "keycompromise", "--no-delete-after-revoke",
                        "--non-interactive"], check=True, timeout=60)
        print(f"Private ACME CA accepted revocation of serial {before.serial_number:X}.")
        return 0
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Local recovery stopped ({type(exc).__name__}). Check local CA and Certbot logs.",
              file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Approved, local-only Smallstep ACME recovery")
    parser.add_argument("--rotate-and-deploy", action="store_true", required=True)
    parser.add_argument("--ca-root", type=Path, required=True, help="Trusted public sandbox root PEM")
    parser.add_argument("--approve-revocation", action="store_true",
                        help="Approve revocation of the previous certificate after trusted TLS verification")
    args = parser.parse_args()
    return run(args.ca_root, args.approve_revocation)


if __name__ == "__main__":
    raise SystemExit(main())
