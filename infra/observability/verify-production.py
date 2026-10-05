"""Verify runtime evidence, not just manifest syntax. Input: audit-production output."""
import json
import sys

current = json.load(open(sys.argv[1]))
assert current['argo']['sync']['status'] == 'Synced'
assert current['argo']['health']['status'] == 'Healthy'
assert not current['argo'].get('conditions')
status = current['deployment']['status']
assert status['readyReplicas'] == status['availableReplicas'] == status['updatedReplicas'] == 3
assert len(current['pods']) == 3
assert all(c['ready'] for p in current['pods'] for c in p['status']['containerStatuses'])
assert len(current['prometheus_targets']) == 3
assert all(t['health'] == 'up' and not t['lastError'] for t in current['prometheus_targets'])
for name, value in current['prometheus'].items():
    assert value['status'] == 'success' and value['data']['result'], name
assert current['loki']['status'] == 'success' and current['loki']['data']['result']
for path, code in current['http'].items():
    assert code == ('404' if path in (
        '/actuator/env', '/actuator/loggers', '/actuator/configprops') else '200'), (path, code)
if len(sys.argv) > 2:
    before = json.load(open(sys.argv[2]))
    assert current['database_counts'] == before['database_counts'], 'Business counts changed'
    previous = {(p['namespace'], p['name']): p for p in before['platform']}
    regressions = []
    for p in current['platform']:
        if p['namespace'] == 'petclinic':
            continue
        old = previous.get((p['namespace'], p['name']))
        if old and all(c['ready'] for c in old['containers']):
            if not all(c['ready'] for c in p['containers']):
                regressions.append(p['name'])
    assert not regressions, regressions
print('PASS: GitOps, 3 replicas, business pages, management boundary, metrics, Loki, database and existing platform readiness')
