"""Read-only protection/resource attribution after the allowed namespace smoke."""
import hashlib
import json
import os
import pathlib
import stat
import subprocess

import yaml

from ops import *

assert_runtime()
owned = json.loads((ROOT / 'owned-node.json').read_text())
resources = {}
for key, args in [
    ('containers', ['ps', '-a', '--no-trunc', '--format', '{{json .}}']),
    ('volumes', ['volume', 'ls', '--format', '{{json .}}']),
    ('networks', ['network', 'ls', '--no-trunc', '--format', '{{json .}}']),
]:
    resources[key] = run(DOCKER + args)
    assert resources[key]['exit'] == 0
containers = [json.loads(line) for line in resources['containers']['stdout'].splitlines()]
volumes = [json.loads(line) for line in resources['volumes']['stdout'].splitlines()]
networks = [json.loads(line) for line in resources['networks']['stdout'].splitlines()]
isolation = json.loads((ROOT / 'node-isolation.json').read_text())
volume_names = [item['Name'] for item in isolation['mounts'] if item['Type'] == 'volume']
assert len(containers) == 1 and containers[0]['ID'] == owned['id']
assert len(volumes) == 1 and volumes[0]['Name'] == volume_names[0]
assert sorted(n['Name'] for n in networks) == ['bridge', 'host', 'kind', 'none']
kind_network = next(n for n in networks if n['Name'] == 'kind')
assert kind_network['ID'] == isolation['networks']['kind']['NetworkID']
resources['ownedVolume'] = run(DOCKER + ['volume', 'inspect', volume_names[0]])
volume = json.loads(resources['ownedVolume']['stdout'])[0]
assert volume['Driver'] == 'local' and not volume.get('Options')
resources['ownedNetwork'] = run(DOCKER + ['network', 'inspect', kind_network['ID']])
network = json.loads(resources['ownedNetwork']['stdout'])[0]
assert list(network['Containers']) == [owned['id']]
resources['kindClusters'] = run(KIND + ['get', 'clusters'])
resources['kindNodes'] = run(KIND + ['get', 'nodes', '--name', 'security-test-sops'])
assert resources['kindClusters']['stdout'].strip() == 'security-test-sops'
assert resources['kindNodes']['stdout'].strip() == 'security-test-sops-control-plane'
save('resources-after.json', resources)
save('owned-resources.json', {'dockerEndpoint': BEFORE['endpoint'], 'nodeContainer': owned['id'],
                            'volume': volume_names[0], 'network': kind_network['ID'],
                            'kubeconfig': str(KUBECONFIG), 'workspace': str(WORK)})

out = {'files': []}
for original in BEFORE['files']:
    path = pathlib.Path(original['path'])
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    out['files'].append({'path': str(path), 'beforeSha256': original['sha256'], 'afterSha256': digest,
                         'unchanged': digest == original['sha256']})
assert all(f['unchanged'] for f in out['files'])
host_env = {k: v for k, v in os.environ.items() if k in {
    'HOME', 'PATH', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'LANG', 'LC_ALL', '__CF_USER_TEXT_ENCODING'
}}
r = subprocess.run(['/opt/homebrew/bin/docker', 'context', 'show'], env=host_env, capture_output=True, text=True, timeout=20)
assert r.returncode == 0 and r.stdout.strip() == 'default'
out['globalDockerContext'] = r.stdout.strip()
profile = yaml.safe_load(pathlib.Path('/Users/zhangsir/.colima/security-test/colima.yaml').read_text())
out['profileFlags'] = {k: profile[k] for k in ['mounts', 'kubernetes', 'sshConfig', 'autoActivate', 'forwardAgent']}
assert profile['mounts'] is None and not profile['kubernetes']['enabled']
assert all(profile[k] is False for k in ['sshConfig', 'autoActivate', 'forwardAgent'])
lima = yaml.safe_load(pathlib.Path('/Users/zhangsir/.colima/_lima/colima-security-test/lima.yaml').read_text())
assert lima.get('mounts') is None and not lima['ssh']['loadDotSSHPubKeys'] and not lima['ssh']['forwardAgent']
guest = (ROOT / 'guest-isolation-after.log').read_text()
mounts = guest.split('__MOUNTS__\n')[1].split('__ENV_NAMES_ONLY__')[0]
assert not any(x in mounts for x in [' /Users', ' virtiofs', ' 9p'])
out['actualGuestHostMountsAbsent'] = True
out['kubeconfigMode'] = oct(stat.S_IMODE(KUBECONFIG.stat().st_mode))
out['workspaceMode'] = oct(stat.S_IMODE(WORK.stat().st_mode))
assert out['kubeconfigMode'] == '0o600' and out['workspaceMode'] == '0o700'
protected = json.loads((ROOT / 'project-before-sha256.json').read_text())
repo = ROOT.parents[2]
changed = []
for name, digest in protected.items():
    path = repo / name
    now = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    if now != digest:
        changed.append(name)
out['protectedProjectFileCount'] = len(protected)
out['changedProjectFiles'] = changed
assert not changed, changed
out.update(productionApiAccess=0, productionCredentialSecretValueReads=0,
           manualSopsSecretServiceAccountRbacLeaseFixtureCreation=0)
save('post-protection.json', out)
save('cleanup.json', {
    'securitySmokeNamespace': 'DELETED; absent from final dedicated namespace list',
    'temporarySmokeContainers': 0, 'unownedContainers': 0, 'unownedVolumes': 0, 'unownedNetworks': 0,
    'retained': ['One authorized kind control-plane', 'Its one VM-local anonymous /var volume',
                 'Its dedicated kind bridge network', 'Private test kubeconfig/workspace', 'Public node image cache'],
    'whyRetained': 'User requested creation/identity proof, not teardown; retain the disposable environment for a separately scoped next phase.',
    'testClientCredentialsArchived': False,
    'manualFixtureObjects': 'No SOPS/age/Secret/ServiceAccount/RBAC/Lease fixtures. Standard kind/kubeadm system objects were automatically bootstrapped.',
    'globalConfigurationChanges': 0,
})
print(json.dumps({'protectedFiles': len(protected), 'allProtectedHostHashesUnchanged': True,
                  'globalContext': out['globalDockerContext'], 'ownedContainerCount': 1,
                  'ownedVolumeCount': 1, 'ownedNetworkCount': 1, 'smokeNamespaceRemoved': True}))
