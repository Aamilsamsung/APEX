"""Validate public certificate bundles against an explicit sandbox trust anchor."""
from functools import lru_cache
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding


def dns_matches(hostname, pattern):
    hostname, pattern = hostname.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return (hostname.count(".") == pattern.count(".")
                and hostname.endswith(pattern[1:]) and bool(hostname.split(".")[0]))
    return hostname == pattern


@lru_cache(maxsize=256)
def validate_bundle(bundle, anchor):
    """Check path, constraints and presentation order. Expiry is scored separately."""
    try:
        chain = x509.load_pem_x509_certificates(bundle)
        root = x509.load_pem_x509_certificate(anchor)
        if chain[0] == root:
            return False, "A trust anchor cannot be used as a leaf"
        for child, issuer in zip(chain, chain[1:]):
            child.verify_directly_issued_by(issuer)
        if chain[-1] != root:
            chain[-1].verify_directly_issued_by(root)
    except (ValueError, TypeError, x509.InvalidVersion, InvalidSignature, UnsupportedAlgorithm, IndexError):
        return False, "Certificate chain is missing an issuer or is misordered"
    return verify_path(tuple(cert.public_bytes(Encoding.PEM) for cert in chain), anchor)


def verify_path(chain, anchor):
    with TemporaryDirectory(prefix="aegis-chain-") as folder:
        root, leaf, issuers = (Path(folder) / name for name in ("root.pem", "leaf.pem", "issuers.pem"))
        root.write_bytes(anchor)
        leaf.write_bytes(chain[0])
        command = ["openssl", "verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
                   "-trusted", str(root), "-no_check_time", "-purpose", "sslserver"]
        if len(chain) > 1:
            issuers.write_bytes(b"".join(chain[1:]))
            command.extend(["-untrusted", str(issuers)])
        try:
            result = subprocess.run([*command, str(leaf)], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            # Avoid caching an environmental failure.
            raise RuntimeError("OpenSSL chain validation unavailable") from None
        return (True, None) if result.returncode == 0 else (False, "OpenSSL rejected the sandbox trust path or CA constraints")
