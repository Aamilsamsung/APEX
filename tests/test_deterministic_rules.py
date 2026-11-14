"""Deterministic risk rules: each reported finding must originate in a rule."""
import pytest
from datetime import timedelta
from backend.core import assess, now


def cert(**overrides):
    base = dict(hostname="service-01.demo.local", sans=["service-01.demo.local"],
                days_remaining=100, key_type="RSA", key_bits=2048,
                signature="sha256", chain_valid=True, self_signed=False,
                validity_days=365, compromised=False, revoked=False)
    base.update(overrides)
    return base


@pytest.mark.parametrize("changes,expected", [
    ({"days_remaining":-1},"EXPIRED"),
    ({"days_remaining":7},"EXPIRING_7D"),
    ({"days_remaining":14},"EXPIRING_14D"),
    ({"days_remaining":30},"EXPIRING_30D"),
    ({"key_bits":1024},"WEAK_RSA"),
    ({"signature":"sha1"},"WEAK_SIGNATURE"),
    ({"sans":["wrong.demo.local"]},"HOSTNAME_MISMATCH"),
    ({"chain_valid":False},"INVALID_CHAIN"),
    ({"self_signed":True},"UNEXPECTED_SELF_SIGNED"),
    ({"validity_days":400},"LONG_VALIDITY"),
    ({"sans":["*.demo.local"],"hostname":"a.b.demo.local"},"WILDCARD_MISUSE"),
    ({"compromised":True},"KEY_COMPROMISE"),
    ({"revoked":True},"REVOKED"),
])
def test_expected_rule(changes,expected):
    assert expected in {f["code"] for f in assess(cert(**changes))}


def test_healthy_certificate_has_no_findings():
    assert assess(cert()) == []


def test_expiry_severity_does_not_round_into_the_earlier_band():
    expires = (now()+timedelta(days=7,hours=12)).isoformat()
    findings = assess(cert(days_remaining=7, expires_at=expires))
    assert [finding['code'] for finding in findings] == ['EXPIRING_14D']


def test_wildcard_covers_one_label_only():
    assert "WILDCARD_MISUSE" not in {f["code"] for f in assess(cert(hostname="a.demo.local",sans=["*.demo.local"]))}
    assert "WILDCARD_MISUSE" in {f["code"] for f in assess(cert(hostname="a.b.demo.local",sans=["*.demo.local"]))}
