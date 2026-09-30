"""Read-only release, registry, PostgreSQL and health acceptance."""
import json, shlex, subprocess
from datetime import datetime, timezone
from pathlib import Path
out = Path(__file__).resolve().parent

def remote(command):
    return subprocess.check_output(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
        '192.168.1.58', command], text=True, timeout=60)

def kube(args):
    return json.loads(remote('sudo -n kubectl ' + args + ' -o json'))

app = kube('get application petclinic -n argocd')
deploy = kube('get deployment petclinic -n petclinic')
pods = kube('get pods -n petclinic -l app=petclinic')['items']
nodes = kube('get nodes')['items']
assert app['status']['sync']['status'] == 'Synced', app['status'].get('conditions')
assert app['status']['health']['status'] == 'Healthy'
assert deploy['status']['observedGeneration'] == deploy['metadata']['generation']
assert deploy['status']['readyReplicas'] == deploy['status']['availableReplicas'] == 3
active = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
assert len(active) == 3
records = []
for pod in active:
    container = pod['spec']['containers'][0]
    status = pod['status']['containerStatuses'][0]
    assert status['ready'], pod['metadata']['name']
    assert container['image'] == '10.0.0.3:30050/petclinic/petclinic:0.7.0-ci-82'
    env = {v['name']: v.get('value') for v in container['env'] if v['name'].startswith(('BUILD_', 'APPLICATION_'))}
    assert env['APPLICATION_VERSION'] == '0.7.0-ci-82'
    assert env['BUILD_GIT_COMMIT'] == 'ffecd50cabe50a214463efc6db7d9e6a92f7d9bf'
    records.append({'name': pod['metadata']['name'], 'node': pod['spec']['nodeName'],
        'image': container['image'], 'imageID': status['imageID'], 'ready': status['ready'],
        'restarts': status['restartCount'], 'release': env})
response = remote("curl --noproxy '*' -fsS -D - -H 'Accept: application/vnd.oci.image.index.v1+json' "
    "http://10.0.0.3:30050/v2/petclinic/petclinic/manifests/0.7.0-ci-82")
headers, body = response.split('\n\n', 1)
index = json.loads(body)
digest = next(line.split(': ', 1)[1].strip() for line in headers.splitlines()
              if line.lower().startswith('docker-content-digest:'))
platforms = {m.get('platform', {}).get('architecture') for m in index['manifests']}
assert {'arm64', 'amd64'} <= platforms
assert all(p['imageID'].endswith(digest) for p in records)
health = json.loads(remote("curl --noproxy '*' -fsS --max-time 25 -H 'Host: petclinic.devops.local' http://192.168.1.58/actuator/health"))
assert health['status'] == 'UP'
sql = "SELECT 'owners',count(*) FROM owners UNION ALL SELECT 'pets',count(*) FROM pets UNION ALL SELECT 'vets',count(*) FROM vets UNION ALL SELECT 'visits',count(*) FROM visits; SELECT id,pet_id,visit_date,description FROM visits WHERE description='Release acceptance 2026-09-30: persisted visit round-trip verification record.';"
db = remote('sudo -n kubectl exec -n ns-data deploy/postgresql -- psql -U postgres -d petclinic -Atc ' + shlex.quote(sql))
assert 'owners|11\npets|13\nvets|6\nvisits|5\n' in db, db
assert db.count('5|1|2026-10-01|Release acceptance') == 1, db
(out / 'production-final-sql.txt').write_text(db)
result = {'verified_at': datetime.now(timezone.utc).isoformat(),
    'argo': {'sync': app['status']['sync']['status'], 'health': app['status']['health']['status'],
        'revision': app['status']['sync']['revision'], 'conditions': app['status'].get('conditions', [])},
    'deployment': {'ready': 3, 'available': 3}, 'pods': records,
    'registry': {'digest': digest, 'manifest': index}, 'health': health,
    'nodes': [{'name': n['metadata']['name'], 'ready': next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready')} for n in nodes],
    'old_terminating_pods': [p['metadata']['name'] for p in pods if p['metadata'].get('deletionTimestamp')],
    'database': db}
(out / 'after-release.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
