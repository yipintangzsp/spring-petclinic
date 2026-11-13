"""Verify served status card and existing REAL records, without POST/scanning."""
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
base = 'http://security.devops.local:17862'
def get(path):
    with op.open(base + path, timeout=5) as r:
        assert r.status == 200
        data = r.read(4 * 1024 * 1024 + 1)
        assert len(data) <= 4 * 1024 * 1024
        return data

body = get('/')
card = body.decode().split('<!-- CANDIDATE_APPROVAL_BEGIN -->')[1].split('<!-- CANDIDATE_APPROVAL_END -->')[0]
for required in ['NOT_READY', 'NOT_STARTED', 'NOT_RUN', 'NOT_APPROVED',
                 'Product 1 / Engagement 1', 'projectKey=petclinic',
                 'sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55']:
    assert required in card
for forbidden in ['PRIVATE KEY-----', 'PRIVATE-TOKEN', 'COSIGN_PASSWORD']:
    assert forbidden not in card
assert get('/') == body
runs = json.loads(get('/api/runs'))['runs']
real = [r for r in runs if r.get('pluginId') == 'gitleaks' and r.get('evidenceClass') == 'REAL' and r.get('state') == 'COMPLETED']
assert any(r.get('scenarioId') == 'clean' and r.get('policyDecision') == 'PASS' for r in real)
assert any(r.get('scenarioId') == 'controlled-finding' and r.get('policyDecision') == 'FAIL' for r in real)
health = json.loads(get('/api/health'))
result = {
    'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'url': base + '/#pipeline-overview', 'http': 200, 'refreshHttp': 200,
    'approvalCardVisible': True, 'releaseReady': 'NO', 'newBuild': 'NOT_STARTED',
    'existingRealCleanAndFindingPreserved': True, 'pageSha256': hashlib.sha256(body).hexdigest(),
    'pageService': health['service'], 'browserClick': 'NOT_TESTED', 'postRequests': 0,
    'releaseCount': 0, 'rolloutCount': 0,
}
with (OUT / 'page-http.json').open('x') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result))
