"""Local-only ACME deployment verification helper.

Run as the local operator. Does not use cloud tokens, issue certificates,
revoke certificates, or change service configuration.
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path
from .local_worker import verify_served_certificate

CERT = "/etc/letsencrypt/live/service-01.demo.local/fullchain.pem"
KEY = "/etc/letsencrypt/live/service-01.demo.local/privkey.pem"
HOST = "service-01.demo.local"


def inspect(cert: str = CERT) -> int:
    for cmd in (
        ["openssl", "x509", "-in", cert, "-noout", "-serial", "-dates", "-ext", "subjectAltName"],
        ["openssl", "x509", "-in", cert, "-noout", "-fingerprint", "-sha256"],
    ):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            print("Certificate inspection unavailable", file=sys.stderr)
            return 1
        if p.returncode:
            print("Cannot read certificate; inspect local file permissions", file=sys.stderr)
            return 1
        print(p.stdout.strip())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only APEX TLS deployment helper")
    parser.add_argument("--inspect", action="store_true", help="Inspect the current ACME certificate")
    parser.add_argument("--verify", action="store_true", help="Compare ACME PEM with loopback TLS endpoint")
    parser.add_argument("--serve", action="store_true", help="Run foreground TLS demo using current ACME cert/key")
    args = parser.parse_args()
    if sum((args.inspect, args.verify, args.serve)) != 1:
        parser.error("Choose exactly one of --inspect, --verify, --serve")
    if args.inspect:
        return inspect()
    if args.verify:
        return 0 if verify_served_certificate(CERT) else 1
    if not Path(CERT).is_file() or not Path(KEY).is_file():
        print("ACME certificate/key missing or inaccessible", file=sys.stderr)
        return 1
    if inspect():
        return 1
    print("Serving pinned demo certificate on 127.0.0.1:8443 (Ctrl+C to stop).", flush=True)
    try:
        return subprocess.call(["openssl", "s_server", "-accept", "127.0.0.1:8443",
                                "-cert", CERT, "-key", KEY, "-www"])
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("OpenSSL server failed to start", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
