"""Bounded GitOps rollout observation with HTTP samples saved as evidence."""
import argparse
import json
import time
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('audit-production.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
parser = argparse.ArgumentParser()
parser.add_argument('revision')
parser.add_argument('output', type=Path)
args = parser.parse_args()
samples = []
deadline = time.monotonic() + 600
while time.monotonic() < deadline:
    deployment = audit.kube('-n petclinic get deploy petclinic')
    app = audit.kube('-n argocd get application petclinic')
    status = deployment['status']
    code = audit.remote("curl --noproxy '*' -sS --max-time 10 -H 'Host: petclinic.devops.local' "
                        "-o /dev/null -w '%{http_code}' http://192.168.1.58/").strip()
    sample = {'time': time.time(), 'http': code, 'ready': status.get('readyReplicas', 0),
              'available': status.get('availableReplicas', 0), 'updated': status.get('updatedReplicas', 0),
              'replicas': status.get('replicas', 0), 'sync': app['status']['sync']['status'],
              'revision': app['status']['sync']['revision'], 'health': app['status']['health']['status']}
    samples.append(sample)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(samples, indent=2))
    if len(samples) % 6 == 1:
        print(json.dumps(sample), flush=True)
    assert code == '200', sample
    assert sample['available'] >= 3, sample
    if sample['revision'] == args.revision and sample['sync'] == 'Synced' and sample['health'] == 'Healthy' \
            and sample['replicas'] == sample['updated'] == sample['available'] == 3:
        print('PASS: converged GitOps rollout; HTTP samples 200 and >=3 available replicas', flush=True)
        break
    time.sleep(5)
else:
    raise SystemExit('FAIL: GitOps rollout did not converge in 600 seconds')
