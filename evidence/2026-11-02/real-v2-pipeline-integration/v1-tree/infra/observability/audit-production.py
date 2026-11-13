"""Read-only Petclinic audit. Never reads Secret values or application identities."""
import argparse
import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def remote(command):
    return subprocess.check_output(
        ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
         '192.168.1.58', command], text=True, timeout=60)


def kube(args):
    return json.loads(remote('sudo -n k3s kubectl ' + args + ' -o json'))


def query(base, path, params=None):
    args = ['curl', '--noproxy', '*', '-fsS', '--max-time', '20', '-G', base + path]
    for key, value in (params or {}).items():
        args += ['--data-urlencode', key + '=' + value]
    return json.loads(remote(shlex.join(args)))


def collect():
    app = kube('-n argocd get application petclinic')
    deployment = kube('-n petclinic get deployment petclinic')
    pods = kube('-n petclinic get pods -l app=petclinic')['items']
    platform = kube('get pods -A')['items']
    result = {
        'verified_at': datetime.now(timezone.utc).isoformat(),
        'argo': {key: app['status'].get(key) for key in ('sync', 'health', 'conditions')},
        'deployment': {'spec': deployment['spec'], 'status': deployment['status']},
        'nodes': [{'name': n['metadata']['name'], 'architecture': n['status']['nodeInfo']['architecture'],
                   'conditions': n['status']['conditions'], 'taints': n['spec'].get('taints', [])}
                  for n in kube('get nodes')['items']],
        'pods': [{'name': p['metadata']['name'], 'node': p['spec']['nodeName'],
                  'status': p['status']} for p in pods],
        'platform': [{'namespace': p['metadata']['namespace'], 'name': p['metadata']['name'],
                      'phase': p['status']['phase'], 'containers': [
                          {'name': c['name'], 'ready': c['ready'], 'restarts': c['restartCount']}
                          for c in p['status'].get('containerStatuses', [])]} for p in platform],
        'resources': kube('-n petclinic get svc,ingress,cm,pvc,hpa,pdb,sa,servicemonitor,prometheusrule'),
        'database_pvc': kube('-n ns-data get pvc postgresql-data'),
    }
    prom = 'http://10.43.111.46:9090'
    targets = query(prom, '/api/v1/targets')['data']['activeTargets']
    result['prometheus_targets'] = [t for t in targets if t['labels'].get('namespace') == 'petclinic']
    result['prometheus'] = {}
    for name, expr in {
        'up': 'up{namespace="petclinic",job="petclinic"}',
        'http': 'sum(http_server_requests_seconds_count{namespace="petclinic"})',
        'jvm': 'jvm_memory_used_bytes{namespace="petclinic",area="heap"}',
        'cpu': 'rate(container_cpu_usage_seconds_total{namespace="petclinic",container="petclinic"}[5m])',
        'memory': 'container_memory_working_set_bytes{namespace="petclinic",container="petclinic"}',
        'restart': 'kube_pod_container_status_restarts_total{namespace="petclinic"}',
    }.items():
        result['prometheus'][name] = query(prom, '/api/v1/query', {'query': expr})
    loki = 'http://10.43.7.197:3100'
    result['loki'] = query(loki, '/loki/api/v1/query_range', {
        'query': '{app="petclinic",namespace="petclinic"}', 'limit': '3', 'since': '10m'})
    urls = ['/', '/owners/find', '/owners', '/pets', '/vets.html', '/system-status', '/platform',
            '/actuator/health', '/actuator/health/readiness', '/actuator/health/liveness',
            '/actuator/prometheus', '/actuator/env', '/actuator/loggers', '/actuator/configprops']
    result['http'] = {}
    for path in urls:
        command = shlex.join(['curl', '--noproxy', '*', '-sS', '--max-time', '20',
            '-H', 'Host: petclinic.devops.local', '-o', '/dev/null', '-w', '%{http_code}',
            'http://192.168.1.58' + path])
        result['http'][path] = remote(command).strip()
    result['database_counts'] = remote('sudo -n k3s kubectl exec -n ns-data deploy/postgresql -- '
        + shlex.join(['psql', '-U', 'postgres', '-d', 'petclinic', '-Atc',
          "SELECT 'owners',count(*) FROM owners UNION ALL SELECT 'pets',count(*) FROM pets "
          "UNION ALL SELECT 'vets',count(*) FROM vets UNION ALL SELECT 'visits',count(*) FROM visits;"]))
    result['host'] = remote('uptime; free -m; df -h /')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = collect()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ('verified_at', 'argo', 'http', 'database_counts')}, indent=2))
