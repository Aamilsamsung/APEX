"""PS2 reference mapping: informational guidance, not claims of certification."""
from __future__ import annotations
from . import core

MITRE = {
    'KEY_COMPROMISE': {'technique':'T1649','name':'Steal or Forge Authentication Certificates',
                       'url':'https://attack.mitre.org/techniques/T1649/'},
    'UNEXPECTED_SELF_SIGNED': {'technique':'T1553.004','name':'Subvert Trust Controls: Install Root Certificate',
                       'url':'https://attack.mitre.org/techniques/T1553/004/'},
}
NIST = {
    'WEAK_RSA': {'reference':'NIST SP 800-57 Part 1 Rev. 5','guidance':'Review minimum cryptographic strength and transition away from RSA keys below 2048 bits.'},
    'WEAK_SIGNATURE': {'reference':'NIST SP 800-57 Part 1 Rev. 5','guidance':'Use modern approved cryptographic algorithms; weak legacy hashes require remediation.'},
    'LONG_VALIDITY': {'reference':'AEGIS demo policy, not a NIST 398-day rule','guidance':'Reduce excessive certificate lifetime under an organization-specific issuance policy.'},
}
def findings_with_references():
    result=[]
    for finding in core.findings():
        item=dict(finding)
        item['mitre_attack']=MITRE.get(item['code'])
        item['policy_reference']=NIST.get(item['code'])
        result.append(item)
    return result

def references():
    return {'mitre_attack':{'source':'MITRE ATT&CK','url':'https://attack.mitre.org/',
                             'note':'Mappings are contextual examples, not proof of an observed attack.'},
            'key_management':{'source':'NIST SP 800-57 Part 1 Rev. 5',
                              'url':'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
                              'note':'Demo thresholds are local policies; not every threshold is mandated by NIST.'},
            'acme':{'source':'RFC 8555','url':'https://datatracker.ietf.org/doc/html/rfc8555',
                    'status':'not configured'},
            'certificate_transparency':{'source':'mock CT replay','status':'sandbox only'}}
