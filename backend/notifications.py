"""Best-effort outbound notifications with no secret material in payloads."""
from __future__ import annotations
import json, os, time, urllib.error, urllib.request, urllib.parse
from . import core

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def notify(incident_id: str, hostname: str, status: str, verification: dict) -> dict:
    url=os.environ.get('AEGIS_NOTIFY_WEBHOOK_URL','').strip()
    payload={'event':'aegis.pki.remediation','incident_id':incident_id,
             'hostname':hostname,'status':status,'tls_verification':verification.get('status','unknown')}
    if not url:
        result={'status':'not_configured','channel':'webhook'}
        core.audit('notification.mocked',{'incident_id':incident_id,'channel':'simulated',
                                         'status':'simulated','payload':payload})
    else:
        try:
            parsed=urllib.parse.urlsplit(url)
            approved_url=parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password
        except ValueError:
            approved_url=False
        if not approved_url:
            result={'status':'failed','channel':'webhook','reason':'Webhook must be an HTTPS URL without embedded credentials'}
        else:
            opener=urllib.request.build_opener(NoRedirect())
            for attempt in range(1,4):
                result={'status':'failed','channel':'webhook','attempts':attempt}
                try:
                    req=urllib.request.Request(url,data=json.dumps(payload).encode(),
                        headers={'Content-Type':'application/json','User-Agent':'AEGIS-PKI-Sandbox/1.0',
                                 'Idempotency-Key':incident_id},method='POST')
                    with opener.open(req,timeout=3) as response:
                        result.update(status='delivered' if 200<=response.status<300 else 'failed',
                                      http_status=response.status)
                    break
                except urllib.error.HTTPError as exc:
                    result['http_status']=exc.code
                    exc.close()
                    if exc.code!=429 and not 500<=exc.code<600:
                        break
                except (OSError, ValueError) as exc:
                    result['reason']=type(exc).__name__
                    if isinstance(exc, ValueError):
                        break
                if attempt<3:
                    time.sleep(.25 * attempt)
    core.audit('notification.delivery',{'incident_id':incident_id,**result})
    return result
