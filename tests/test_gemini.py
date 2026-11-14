import io
import json

import pytest

from backend import core


@pytest.mark.parametrize('configured_model', [None, 'models/gemini-3.5-flash-lite'])
def test_gemini_explains_rules_without_sending_certificate_details(monkeypatch, configured_model):
    finding = {
        'id': 'private-certificate:EXPIRED',
        'code': 'EXPIRED',
        'severity': 'critical',
        'message': 'Sensitive certificate details',
    }
    monkeypatch.setattr(core, 'findings', lambda: [finding])
    monkeypatch.setenv('GEMINI_API_KEY', 'synthetic-test-key')
    if configured_model is None:
        monkeypatch.delenv('GEMINI_MODEL', raising=False)
    else:
        monkeypatch.setenv('GEMINI_MODEL', configured_model)

    def generate(request, timeout):
        assert request.full_url.endswith('/models/gemini-3.5-flash-lite:generateContent')
        payload = json.loads(request.data)
        assert payload['generationConfig'] == {'responseMimeType': 'application/json'}
        assert json.loads(payload['contents'][0]['parts'][0]['text']) == [
            {'id': '1', 'code': 'EXPIRED', 'severity': 'critical'}
        ]
        recommendations = [
            {'finding_id': 'unknown', 'priority': 1, 'explanation': 'Discard this finding.'},
            {'finding_id': '1', 'priority': 1, 'explanation': 'Renew the expired certificate.'},
        ]
        return io.StringIO(json.dumps({'candidates': [{'content': {'parts': [
            {'thought': True, 'text': 'Discard this thought.'},
            {'text': json.dumps({'recommendations': recommendations})},
        ]}}]}))

    monkeypatch.setattr(core.urllib.request, 'urlopen', generate)
    result = core.explain_with_llm()

    assert result['mode'] == 'gemini-llm'
    assert result['recommendations'] == [{
        'finding_id': finding['id'],
        'severity': 'critical',
        'priority': 1,
        'explanation': 'Renew the expired certificate.',
    }]
