from backend import notifications, acme_client
from urllib.error import HTTPError
import json
import pytest

def test_notification_unconfigured(monkeypatch):
    monkeypatch.delenv('AEGIS_NOTIFY_WEBHOOK_URL',raising=False)
    monkeypatch.setattr(notifications.core,'audit',lambda *args:None)
    result=notifications.notify('incident-1','service-01.demo.local','resolved',{'status':'verified'})
    assert result['status']=='not_configured'

def test_notification_rejects_http(monkeypatch):
    monkeypatch.setenv('AEGIS_NOTIFY_WEBHOOK_URL','http://example.com/hook')
    monkeypatch.setattr(notifications.core,'audit',lambda *args:None)
    result=notifications.notify('incident-1','service-01.demo.local','resolved',{'status':'verified'})
    assert result['status']=='failed'


def test_notification_retries_transient_failure_with_same_payload(monkeypatch):
    sent = []
    class Receiver:
        status = 204

        def open(self, request, timeout):
            sent.append((request.get_header('Idempotency-key'), json.loads(request.data)))
            if len(sent) == 1:
                raise HTTPError(request.full_url, 503, 'Unavailable', {}, None)
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setenv('AEGIS_NOTIFY_WEBHOOK_URL', 'https://receiver.demo.local/secret')
    monkeypatch.setattr(notifications.urllib.request, 'build_opener', lambda *args: Receiver())
    monkeypatch.setattr(notifications.core, 'audit', lambda *args: None)
    result = notifications.notify('incident-1', 'service-01.demo.local', 'resolved', {'status':'verified'})
    assert result == {'status':'delivered','channel':'webhook','attempts':2,'http_status':204}
    assert sent[0] == sent[1] == ('incident-1', {
        'event':'aegis.pki.remediation','incident_id':'incident-1','hostname':'service-01.demo.local',
        'status':'resolved','tls_verification':'verified',
    })

def test_acme_rejects_untrusted_directory():
    with pytest.raises(ValueError):
        acme_client.issue_via_acme('service-01.demo.local','http://localhost/directory','data/acme')

def test_acme_rejects_external_names():
    with pytest.raises(ValueError):
        acme_client.issue_via_acme('example.com','https://localhost/acme/directory','data/acme')
