from backend import notifications, acme_client
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

def test_acme_rejects_untrusted_directory():
    with pytest.raises(ValueError):
        acme_client.issue_via_acme('service-01.demo.local','http://localhost/directory','data/acme')

def test_acme_rejects_external_names():
    with pytest.raises(ValueError):
        acme_client.issue_via_acme('example.com','https://localhost/acme/directory','data/acme')
