"""Best-effort outbound notifications with no secret material in payloads."""
from __future__ import annotations
import json, os, urllib.request, urllib.parse
from . import core

def notify(incident_id: str, hostname: str, status: str, verification: dict) -> dict:
    url=os.environ.get('AEGIS_NOTIFY_WEBHOOK_URL','').strip()
    payload={'event':'aegis.pki.remediation','incident_id':incident_id,
             'hostname':hostname,'status':status,'tls_verification':verification.get('status','unknown')}
    if not url:
        result={'status':'not_configured','channel':'webhook'}
    else:
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
            result={'status':'failed','channel':'webhook','reason':'Webhook must be an HTTPS URL without embedded credentials'}
        else:
            try:
                req=urllib.request.Request(url,data=json.dumps(payload).encode(),
                    headers={'Content-Type':'application/json','User-Agent':'AEGIS-PKI-Sandbox/1.0'},method='POST')
                with urllib.request.urlopen(req,timeout=5) as response:
                    result={'status':'delivered' if 200<=response.status<300 else 'failed',
                            'channel':'webhook','http_status':response.status}
            except Exception as exc:
                result={'status':'failed','channel':'webhook','reason':type(exc).__name__}
    core.audit('notification.delivery',{'incident_id':incident_id,**result})
    return result
