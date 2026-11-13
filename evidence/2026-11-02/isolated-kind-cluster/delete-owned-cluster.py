"""Prepared only. Explicitly run later to delete this exact disposable cluster."""
import hashlib
import json

from ops import *

assert_runtime()
owned = json.loads((ROOT / 'owned-resources.json').read_text())
identity = json.loads((ROOT / 'cluster-identity.json').read_text())
assert hashlib.sha256(KUBECONFIG.read_bytes()).hexdigest() == identity['kubeconfigSha256']
nodes = run(DOCKER + ['ps', '-aq', '--no-trunc', '--filter', 'label=io.x-k8s.kind.cluster=security-test-sops'])
assert nodes['exit'] == 0 and nodes['stdout'].split() == [owned['nodeContainer']]
node = json.loads(run(DOCKER + ['inspect', owned['nodeContainer']])['stdout'])[0]
assert node['Name'] == '/security-test-sops-control-plane'
assert node['Config']['Labels']['io.x-k8s.kind.cluster'] == 'security-test-sops'
result = run(KIND + ['delete', 'cluster', '--name', 'security-test-sops', '--kubeconfig', str(KUBECONFIG)], 120)
save('later-explicit-cluster-deletion.json', result)
assert result['exit'] == 0, result
print('Owned kind cluster deleted. Recheck owned network/volume and private workspace before final teardown; no global/default endpoint used.')
