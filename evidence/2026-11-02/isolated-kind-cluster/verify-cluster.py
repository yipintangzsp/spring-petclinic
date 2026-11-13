"""Verify owned Docker node/CA/endpoint before any explicit Kubernetes API request."""
import base64
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import stat
import urllib.parse

from ops import *

assert_runtime()
owned = json.loads((ROOT / 'owned-node.json').read_text())
result = run(DOCKER + ['inspect', owned['id']])
assert result['exit'] == 0
node = json.loads(result['stdout'])[0]
assert node['Id'] == owned['id'] and node['Name'] == '/security-test-sops-control-plane'
assert node['Config']['Labels']['io.x-k8s.kind.cluster'] == 'security-test-sops'
assert node['State']['Running'] and node['HostConfig']['NetworkMode'] != 'host'
assert node['HostConfig']['Privileged'] is True  # Standard kind requirement, explicitly authorized.
assert all(m['Type'] != 'bind' or (m['Source'] == '/lib/modules' and not m['RW']) for m in node['Mounts']), node['Mounts']
env_names = [x.split('=', 1)[0] for x in node['Config'].get('Env', [])]
assert not any(name.startswith(('AWS_', 'SOPS_', 'AGE_', 'BUSINESS_AGE', 'JENKINS_', 'HARBOR_')) or name in ['SSH_AUTH_SOCK', 'DOCKER_AUTH_CONFIG'] for name in env_names)
save('node-isolation.json', {
    'id': node['Id'], 'name': node['Name'], 'imageId': node['Image'],
    'labels': node['Config']['Labels'], 'mounts': node['Mounts'], 'envNames': env_names,
    'networkMode': node['HostConfig']['NetworkMode'], 'standardKindPrivileged': True,
    'noAdditionalPrivilegeOptionsRequested': True, 'portBindings': node['HostConfig']['PortBindings'],
    'networks': node['NetworkSettings']['Networks'], 'sourceScope': 'Bind sources are inside the already-proven isolated VM; no host HOME/production mount.',
})

# These commands read the dedicated test kubeconfig only, and make no API calls.
meta = run(KUBECTL + ['config', 'view', '--minify', '-o', 'json'])
assert meta['exit'] == 0
config = json.loads(meta['stdout'])
assert len(config['clusters']) == len(config['contexts']) == 1
assert config['current-context'] == 'kind-security-test-sops'
assert config['clusters'][0]['name'] == 'kind-security-test-sops'
cluster = config['clusters'][0]['cluster']
assert not cluster.get('insecure-skip-tls-verify', False)
server = cluster['server']
url = urllib.parse.urlparse(server)
assert url.scheme == 'https' and url.hostname == '127.0.0.1'
assert server not in ['https://127.0.0.1:26443', 'https://127.0.0.1:63731']
bindings = node['HostConfig']['PortBindings']['6443/tcp']
assert len(bindings) == 1 and bindings[0]['HostIp'] == '127.0.0.1'
assert url.port == int(bindings[0]['HostPort'])
assert stat.S_IMODE(WORK.stat().st_mode) == 0o700
assert stat.S_IMODE(KUBECONFIG.stat().st_mode) == 0o600

# Only the public CA field is extracted. Never archive test client key/cert or whole config.
ca_result = run(KUBECTL + ['config', 'view', '--minify', '--raw', '-o', 'jsonpath={.clusters[0].cluster.certificate-authority-data}'])
assert ca_result['exit'] == 0
ca_pem = base64.b64decode(ca_result['stdout']).decode()
ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
ca_sha = hashlib.sha256(ca_der).hexdigest()
node_ca = run(DOCKER + ['exec', owned['id'], 'sh', '-c', 'openssl x509 -in /etc/kubernetes/pki/ca.crt -outform DER | sha256sum'])
assert node_ca['exit'] == 0 and node_ca['stdout'].split()[0] == ca_sha
tls_context = ssl.create_default_context(cadata=ca_pem)
with socket.create_connection((url.hostname, url.port), timeout=10) as tcp:
    with tls_context.wrap_socket(tcp, server_hostname=url.hostname) as secure:
        tls_leaf_sha = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
proof = {
    'cluster': 'security-test-sops', 'dockerEndpoint': BEFORE['endpoint'],
    'nodeContainerId': owned['id'], 'nodeContainerName': node['Name'],
    'apiEndpoint': server, 'dedicatedKubeconfig': str(KUBECONFIG),
    'kubeconfigSha256': hashlib.sha256(KUBECONFIG.read_bytes()).hexdigest(),
    'caFingerprintSha256DER': ca_sha, 'nodeCAEqualsKubeconfigCA': True,
    'endpointTLSVerifiedAgainstOwnCA': True, 'apiLeafFingerprintSha256DER': tls_leaf_sha,
    'apiEndpointBoundToOwnedContainer': True, 'userKubeconfigLoaded': False,
    'credentialMaterialArchived': False, 'preAPIBoundaryCheck': 'PASS',
}
save('cluster-identity-pre-api.json', proof)

# API requests are now limited to the positively identified new test endpoint.
observations = {}
for key, args in [
    ('nodes', ['get', 'nodes', '-o', 'json']),
    ('namespaces', ['get', 'namespaces', '-o', 'json']),
    ('clusterInfo', ['cluster-info']),
    ('version', ['version', '-o', 'json']),
]:
    observations[key] = run(KUBECTL + args, 45)
    save('cluster-observations.json', observations)
    assert observations[key]['exit'] == 0, (key, observations[key])
nodes = json.loads(observations['nodes']['stdout'])['items']
assert len(nodes) == 1 and nodes[0]['metadata']['name'] == 'security-test-sops-control-plane'
n = nodes[0]
assert n['status']['nodeInfo']['architecture'] == 'arm64'
assert any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions'])
ns = {x['metadata']['name']: x['metadata']['uid'] for x in json.loads(observations['namespaces']['stdout'])['items']}
production_uid = '639e5426-bc1f-4d37-a844-6a31b7685744'
assert ns['kube-system'] != production_uid
proof.update(kubeSystemUID=ns['kube-system'], defaultNamespaceUID=ns['default'],
             nodeName=n['metadata']['name'], nodeUID=n['metadata']['uid'],
             nodeArchitecture=n['status']['nodeInfo']['architecture'],
             nodeContainerRuntime=n['status']['nodeInfo']['containerRuntimeVersion'],
             kubernetesVersion=n['status']['nodeInfo']['kubeletVersion'])
save('cluster-identity.json', proof)
save('production-identity-comparison.json', {
    'source': 'Existing historical evidence only; no production API or certificate retrieval.',
    'productionEvidence': 'evidence/2026-11-02/sops-isolation-design/identity-assessment.json',
    'endpoint': {'knownProductionTunnel': 'https://127.0.0.1:26443', 'new': server, 'differs': True},
    'namespaceUID': {'productionKubeSystemUID': production_uid, 'newKubeSystemUID': ns['kube-system'], 'differs': True},
    'CA': {'productionFingerprint': 'NOT_AVAILABLE_IN_EXISTING_ARCHIVE', 'newFingerprint': ca_sha, 'comparison': 'NOT_COMPARABLE; no production credential/config certificate extraction or API attempted'},
    'node': {'knownProductionNames': ['devops', 'aliyun-worker', 'ucloud-worker'], 'new': n['metadata']['name'], 'differs': True},
    'clusterConfigIdentity': {'knownProductionClusterAlias': 'orbstack', 'new': 'kind-security-test-sops', 'differs': True},
    'kubeconfig': {'productionPath': '/Users/zhangsir/.kube/config', 'new': str(KUBECONFIG), 'differs': True},
    'productionApiCalls': 0,
})

assert 'security-smoke' not in ns
smoke = {}
try:
    smoke['create'] = run(KUBECTL + ['create', 'namespace', 'security-smoke'])
    save('namespace-smoke.json', smoke)
    assert smoke['create']['exit'] == 0, smoke
    smoke['readMetadata'] = run(KUBECTL + ['get', 'namespace', 'security-smoke', '-o', 'jsonpath={.metadata.name}{"|"}{.metadata.uid}{"\\n"}'])
    assert smoke['readMetadata']['exit'] == 0 and smoke['readMetadata']['stdout'].startswith('security-smoke|')
finally:
    if smoke.get('create', {}).get('exit') == 0:
        smoke['delete'] = run(KUBECTL + ['delete', 'namespace', 'security-smoke', '--wait=true', '--timeout=90s'], 100)
        save('namespace-smoke.json', smoke)
smoke['namespacesAfter'] = run(KUBECTL + ['get', 'namespaces', '-o', 'json'])
assert smoke['namespacesAfter']['exit'] == 0
assert all(x['metadata']['name'] != 'security-smoke' for x in json.loads(smoke['namespacesAfter']['stdout'])['items'])
assert smoke['delete']['exit'] == 0
smoke['status'] = 'PASS'
save('namespace-smoke.json', smoke)
print(json.dumps({'identity': proof, 'namespaceSmoke': 'PASS', 'namespaceRemoved': True}))
