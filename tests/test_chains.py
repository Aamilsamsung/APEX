from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID

from backend import core
from backend.chains import validate_bundle


def issue(name, issuer, issuer_key, key, ca, path_length=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(core.now() - timedelta(days=1))
            .not_valid_after(core.now() + timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca, path_length), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def test_ordered_intermediate_path_and_ca_constraints():
    root_key, issuer_key, leaf_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    root = issue("root", None, root_key, root_key, True, 1)
    issuer = issue("intermediate", root, root_key, issuer_key, True, 0)
    non_ca = issue("intermediate", root, root_key, issuer_key, False)
    leaf = issue("leaf.demo.local", issuer, issuer_key, leaf_key, False)

    anchor = root.public_bytes(Encoding.PEM)
    leaf_pem = leaf.public_bytes(Encoding.PEM)
    issuer_pem = issuer.public_bytes(Encoding.PEM)
    assert validate_bundle(leaf_pem + issuer_pem, anchor) == (True, None)
    assert not validate_bundle(leaf_pem, anchor)[0]
    assert not validate_bundle(leaf_pem + anchor + issuer_pem, anchor)[0]
    assert not validate_bundle(leaf_pem + non_ca.public_bytes(Encoding.PEM), anchor)[0]
