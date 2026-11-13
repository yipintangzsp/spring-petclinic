"""Reproduce and repair four faults using disposable Pods, never production resources."""
import argparse
import importlib.util
import json
import shlex
import subprocess
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('audit-production.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path)
args = parser.parse_args()
namespace = 'petclinic-drills-20261005'
owner = 'petclinic-isolated-drills'
image = audit.kube('-n petclinic get deploy petclinic')['spec']['template']['spec']['containers'][0]['image']
assert image.startswith('10.0.0.3:30050/petclinic/petclinic:') and not image.endswith(':latest')


def command(parts, body=None):
    cmd = shlex.join(['sudo', '-n', 'k3s', 'kubectl'] + parts)
    return subprocess.check_output(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
        '192.168.1.58', cmd], input=json.dumps(body) if body else None, text=True, timeout=75)


def create(resource):
    return command(['create', '-f', '-'], resource)


def pod(name, fault=None):
    container = {'name': 'drill', 'image': image, 'imagePullPolicy': 'IfNotPresent',
        'command': ['/bin/sh', '-c', 'sleep 600'],
        'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '64Mi'}},
        'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}
    if fault == 'image':
        container['image'] += '-drill-missing'
    elif fault == 'crash':
        container['command'] = ['/bin/sh', '-c', 'exit 42']
    elif fault == 'readiness':
        container['readinessProbe'] = {'exec': {'command': ['/bin/sh', '-c', 'test -f /tmp/drill-ready']},
                                       'periodSeconds': 2, 'timeoutSeconds': 1}
    elif fault == 'pending':
        container['resources']['requests']['cpu'] = '10000'
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace,
        'labels': {'app': 'petclinic-drill', 'app.kubernetes.io/managed-by': owner}},
        'spec': {'nodeSelector': {'kubernetes.io/hostname': 'devops'},
                 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 1,
                 'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001},
                 'containers': [container]}}


def wait(name, predicate):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        value = json.loads(command(['-n', namespace, 'get', 'pod', name, '-o', 'json']))
        if predicate(value):
            return value
        time.sleep(2)
    raise RuntimeError('Timeout waiting for ' + name)


def ready(value):
    return any(c['type'] == 'Ready' and c['status'] == 'True' for c in value['status'].get('conditions', []))


def waiting_reason(value):
    statuses = value['status'].get('containerStatuses', [])
    return statuses[0].get('state', {}).get('waiting', {}).get('reason') if statuses else None


def crash_backoff(value, name):
    statuses = value['status'].get('containerStatuses', [])
    if not statuses or statuses[0].get('restartCount', 0) < 2:
        return False
    if statuses[0].get('lastState', {}).get('terminated', {}).get('exitCode') != 42:
        return False
    if waiting_reason(value) == 'CrashLoopBackOff':
        return True
    events = json.loads(command(['-n', namespace, 'get', 'events',
        '--field-selector=involvedObject.name=' + name, '-o', 'json']))['items']
    # Some kubelet/runtime versions retain terminated/Error during backoff.
    return any(e['reason'] == 'BackOff' and 'restarting failed container' in e.get('message', '')
               for e in events)


def delete(name):
    value = json.loads(command(['-n', namespace, 'get', 'pod', name, '-o', 'json']))
    assert value['metadata']['labels']['app.kubernetes.io/managed-by'] == owner
    command(['-n', namespace, 'delete', 'pod', name, '--wait=true', '--timeout=30s'])


existing = json.loads(command(['get', 'namespace', '-o', 'json']))['items']
assert not any(n['metadata']['name'] == namespace for n in existing), 'Reserved drill namespace already exists'
records = {'image': image, 'namespace': namespace, 'cases': [], 'cleanup': False}
create({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace,
        'labels': {'app.kubernetes.io/managed-by': owner}}})
try:
    create({'apiVersion': 'v1', 'kind': 'ResourceQuota', 'metadata': {'name': 'drill-budget',
            'namespace': namespace}, 'spec': {'hard': {'pods': '2', 'requests.memory': '64Mi',
                                                     'limits.memory': '128Mi'}}})
    for fault in ['image', 'crash', 'readiness', 'pending']:
        name = 'drill-' + fault
        create(pod(name, fault))
        if fault == 'image':
            broken = wait(name, lambda p: waiting_reason(p) == 'ImagePullBackOff')
        elif fault == 'crash':
            broken = wait(name, lambda p: crash_backoff(p, name))
            assert broken['status']['containerStatuses'][0]['lastState']['terminated']['exitCode'] == 42
        elif fault == 'readiness':
            broken = wait(name, lambda p: p['status']['phase'] == 'Running' and not ready(p)
                and any(e['reason'] == 'Unhealthy' and 'Readiness probe failed' in e.get('message', '')
                    for e in json.loads(command(['-n', namespace, 'get', 'events',
                        '--field-selector=involvedObject.name=' + name, '-o', 'json']))['items']))
        else:
            broken = wait(name, lambda p: any(c['type'] == 'PodScheduled' and c.get('reason') == 'Unschedulable'
                          and 'Insufficient cpu' in c.get('message', '') for c in p['status'].get('conditions', [])))
        events = json.loads(command(['-n', namespace, 'get', 'events',
            '--field-selector=involvedObject.name=' + name, '-o', 'json']))['items']
        if fault == 'readiness':
            command(['-n', namespace, 'exec', name, '--', 'touch', '/tmp/drill-ready'])
        elif fault == 'image':
            command(['-n', namespace, 'patch', 'pod', name, '--type=json', '--patch-file=/dev/stdin'],
                    [{'op': 'replace', 'path': '/spec/containers/0/image', 'value': image}])
        else:
            delete(name)
            create(pod(name))
        fixed = wait(name, ready)
        records['cases'].append({'case': fault, 'failure_status': broken['status'],
            'events': [{'reason': e['reason'], 'message': e.get('message')} for e in events],
            'recovery_status': fixed['status'], 'recovered': True})
        delete(name)
        print('PASS:', fault, 'reproduced and recovered', flush=True)
finally:
    value = json.loads(command(['get', 'namespace', namespace, '-o', 'json']))
    assert value['metadata']['labels']['app.kubernetes.io/managed-by'] == owner
    pods = json.loads(command(['-n', namespace, 'get', 'pods', '-o', 'json']))['items']
    assert all(p['metadata']['labels'].get('app.kubernetes.io/managed-by') == owner for p in pods)
    command(['delete', 'namespace', namespace, '--wait=true', '--timeout=60s'])
    records['cleanup'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2))
print('PASS: disposable namespace removed; no production Pod, Service, Secret, PVC or database changed')
