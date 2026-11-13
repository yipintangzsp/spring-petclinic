"""Terraform executes only here, inside the restricted Job, never in Jenkins."""
import base64
import errno
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from sandbox import enforce

LAB = 'tf-remote-lab'
STORE = 'terraform-state'
EXEC = 'terraform-execution'
OWNER = 'terraform-remote-lab'
SECRET = 'tfstate-default-petclinic-remote-v1'
LEASE = 'lock-' + SECRET
ADDRESS = 'kubernetes_config_map_v1.environment'
PROBE = 'terraform_data.coordination_probe[0]'
BIN = '/usr/local/bin/terraform'
SOURCE = Path('/opt/terraform/source')
WORK = Path('/work')
ACTIVE = []
TOKEN = ''
RECORDS = []


def sha(value):
    return hashlib.sha256(value).hexdigest()


def inspect_plan(value, cleanup=False):
    changes = value.get('resource_changes', [])
    if len(changes) != 2 or {x['address'] for x in changes} != {ADDRESS, PROBE}:
        raise RuntimeError('Foreign or missing state resource')
    result = []
    for x in changes:
        actions, after = x['change']['actions'], x['change'].get('after')
        if x['address'] == ADDRESS:
            if actions not in [['no-op'], ['create'], ['update']]:
                raise RuntimeError('Real ConfigMap cannot be removed/replaced')
            meta = after['metadata'][0]
            if meta['name'] != 'environment-manifest' or meta['namespace'] != LAB or meta['labels'].get('petclinic.devops.local/owner') != OWNER:
                raise RuntimeError('Foreign ConfigMap scope')
            if after['data'] != {'config_revision': 'v1', 'managed_by': 'terraform', 'scenario': 'petclinic-devops-study'}:
                raise RuntimeError('Unexpected payload')
        elif actions != (['delete'] if cleanup else ['create']):
            raise RuntimeError('Only the new virtual probe may be changed')
        if actions != ['no-op']:
            result.append({'address': x['address'], 'actions': actions})
    if cleanup and result != [{'address': PROBE, 'actions': ['delete']}]:
        raise RuntimeError('Cleanup may remove only the virtual probe')
    return result


def stop_children(*unused):
    for p in ACTIVE:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGINT)
    for p in ACTIVE:
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
    raise InterruptedError('Job interrupted; owned process groups stopped')


def api(method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {'Content-Type': 'application/json'}
    value = TOKEN if token is None else token
    if value:
        headers['Authorization'] = 'Bearer ' + value
    request = urllib.request.Request(os.environ['API_SERVER'] + path, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile='/var/run/terraform-identity/ca.crt')
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def require_api(method, path, body=None, expected=200):
    status, value = api(method, path, body)
    if status != expected:
        raise RuntimeError(f'API {method} {path}: HTTP{status}')
    return value


def icmp_rejection(ancillary):
    for level, kind, data in ancillary:
        if level == socket.SOL_IP and kind == 11 and len(data) >= 16:
            number, origin, icmp_type, code, _, info, extra = struct.unpack('=IBBBBII', data[:16])
            if number == errno.ECONNREFUSED and origin == 2 and icmp_type == 3 and code == 3:
                return {'errno': number, 'origin': 'kernel-ICMP', 'icmp_type': icmp_type, 'icmp_code': code}
    raise RuntimeError('Connection refusal without kernel ICMP policy-rejection evidence')


def canary_attempt(host):
    canary = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    canary.setsockopt(socket.SOL_IP, 11, 1)
    canary.settimeout(0.5)
    try:
        canary.connect((host, 6443))
        return None
    except (TimeoutError, socket.timeout):
        return {'kind': 'timeout'}
    except OSError as error:
        if error.errno == errno.ECONNREFUSED:
            _, ancillary, _, _ = canary.recvmsg(1, 256, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
            return icmp_rejection(ancillary)
        if error.errno in [errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH]:
            return {'errno': error.errno}
        raise RuntimeError('Unexpected canary rejection errno=' + str(error.errno)) from error
    finally:
        canary.close()


def wait_for_canary_policy(host, connect=canary_attempt, clock=time.monotonic, sleep=time.sleep):
    started = clock()
    attempts = 0
    while clock() - started < 15:
        attempts += 1
        proof = connect(host)
        if proof is not None:
            return {**proof, 'readiness_attempts': attempts, 'readiness_wait_seconds': round(clock() - started, 3), 'initially_reachable': attempts > 1}
        # A reachable canary never authorizes token reads or Terraform startup.
        # Wait for the CNI to install its per-Pod rules, then require real rejection.
        sleep(0.25)
    raise RuntimeError('Network policy readiness timed out; no token read or Terraform execution allowed')


def probe_isolation(sandbox):
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    for key, expected in [('NoNewPrivs', '1'), ('Seccomp', '2')]:
        if status[key].strip() != expected:
            raise RuntimeError('Missing kernel isolation: ' + key)
    if int(status['CapEff'].strip(), 16) != 0 or int(status['Seccomp_filters'].strip()) < 2:
        raise RuntimeError('Capabilities or additional seccomp filter incorrect')
    profile = Path('/proc/self/attr/current').read_text().strip()
    if 'unconfined' in profile or 'enforce' not in profile:
        raise RuntimeError('Enforcing AppArmor profile required')
    if os.getuid() != 65532 or os.getgid() != 65532 or not (os.statvfs('/').f_flag & os.ST_RDONLY):
        raise RuntimeError('Non-root read-only filesystem required')
    forbidden = ['/var/jenkins_home', '/var/run/docker.sock', '/run/containerd/containerd.sock', '/etc/rancher/k3s/k3s.yaml', '/var/run/secrets/kubernetes.io/serviceaccount/token']
    if any(Path(p).exists() for p in forbidden):
        raise RuntimeError('Host/Jenkins/admin path exposed')
    if any(os.environ.get(k) for k in ['JENKINS_HOME', 'GITLAB_TOKEN', 'HARBOR_PASS', 'SSH_AUTH_SOCK', 'DOCKER_HOST']):
        raise RuntimeError('Controller credentials exposed')
    try:
        with open('/etc/terraform-isolation-probe', 'x'):
            pass
    except OSError as error:
        if error.errno not in [errno.EROFS, errno.EACCES]:
            raise
    else:
        raise RuntimeError('Root filesystem unexpectedly writable')
    network = []
    host = urllib.parse.urlparse(os.environ['API_SERVER']).hostname
    targets = [('node-ssh', host, 22), ('jenkins-port', host, 8080), ('non-api-https', '198.51.100.1', 443), ('database-port', host, 3306)]
    for name, host, port in targets:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((host, port))
        except OSError as error:
            if error.errno not in [errno.EPERM, errno.EACCES]:
                raise RuntimeError('Kernel policy did not reject ' + name) from error
            network.append({'target': name, 'port': port, 'errno': error.errno, 'kernel_denied': True})
        else:
            raise RuntimeError('Forbidden network reachable: ' + name)
        finally:
            s.close()
    for family, kind in [(socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_INET6, socket.SOCK_DGRAM), (socket.AF_PACKET, socket.SOCK_RAW)]:
        try:
            s = socket.socket(family, kind)
        except OSError as error:
            if error.errno != errno.EPERM:
                raise
        else:
            s.close()
            raise RuntimeError('Forbidden socket family/type allowed')
    rejection = wait_for_canary_policy(os.environ['CANARY_IP'])
    return {'network_policy_canary_blocked': True, 'canary_rejection': rejection, 'uid': os.getuid(), 'gid': os.getgid(), 'root_read_only': True, 'admin_paths_absent': forbidden,
            'no_new_privileges': True, 'effective_capabilities': 0, 'seccomp_mode': 2,
            'seccomp_filters': int(status['Seccomp_filters'].strip()), 'apparmor': profile,
            'sandbox': sandbox, 'network_denials': network, 'udp_raw_denied': True}


def make_environment(directory, token):
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(directory / 'home'), 'TMPDIR': '/work/tmp',
            'LANG': 'C.UTF-8', 'TF_IN_AUTOMATION': '1', 'TF_INPUT': '0', 'CHECKPOINT_DISABLE': '1',
            'GOMAXPROCS': '1', 'GOMEMLIMIT': '192MiB', 'TF_CLI_CONFIG_FILE': '/opt/terraform/terraform.rc',
            'KUBE_HOST': os.environ['API_SERVER'], 'KUBE_TOKEN': token,
            'KUBE_CLUSTER_CA_CERT_DATA': Path('/var/run/terraform-identity/ca.crt').read_text(),
            'KUBE_IN_CLUSTER_CONFIG': 'false', 'KUBE_CONFIG_PATH': str(directory / 'home/public-kubeconfig.json')}


def tf(directory, name, args, expected=(0,), token=None):
    print('TF_ISOLATED_STEP ' + name, flush=True)
    env = make_environment(directory, TOKEN if token is None else token)
    start = time.monotonic()
    p = subprocess.Popen([BIN, *args], cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    ACTIVE.append(p)
    try:
        out, err = p.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGINT)
        out, err = p.communicate(timeout=8)
        raise RuntimeError(name + ' timed out')
    finally:
        if p.poll() is not None:
            ACTIVE.remove(p)
    (directory / (name + '.log')).write_text((out + err).replace(TOKEN, '[REDACTED]'))
    RECORDS.append({'step': name, 'exit': p.returncode, 'seconds': round(time.monotonic() - start, 3)})
    if p.returncode not in expected:
        diagnostic = err[-2000:].replace(TOKEN, '[REDACTED]') if TOKEN else err[-2000:]
        print('TF_ISOLATED_DIAGNOSTIC:' + diagnostic, flush=True)
        raise RuntimeError(name + ' failed')
    return out, err


def directory(name, mode):
    d = WORK / name
    (d / 'home').mkdir(parents=True, mode=0o700)
    (d / 'main.tf').write_bytes((SOURCE / ('terraform' if mode == 'plan' else 'remote') / 'main.tf').read_bytes())
    (d / '.terraform.lock.hcl').write_bytes((SOURCE / 'terraform/.terraform.lock.hcl').read_bytes())
    cfg = {'apiVersion': 'v1', 'kind': 'Config', 'clusters': [{'name': 'local', 'cluster': {'server': os.environ['API_SERVER'], 'certificate-authority-data': base64.b64encode(Path('/var/run/terraform-identity/ca.crt').read_bytes()).decode()}}],
           'users': [{'name': 'scoped', 'user': {}}], 'contexts': [{'name': 'scoped', 'context': {'cluster': 'local', 'user': 'scoped'}}], 'current-context': 'scoped'}
    (d / 'home/public-kubeconfig.json').write_text(json.dumps(cfg))
    if mode == 'plan':
        (d / 'input.auto.tfvars.json').write_text(json.dumps({'namespace_name': 'tf-devops-lab', 'scenario': 'petclinic-devops-study', 'config_revision': 'v1', 'kubeconfig_path': str(d / 'home/public-kubeconfig.json')}))
    return d


def initialize(d):
    tf(d, d.name + '-init', ['init', '-input=false', '-lockfile=readonly', '-no-color'])
    tf(d, d.name + '-validate', ['validate', '-no-color'])
    if (d / '.terraform/terraform.tfstate').exists() and TOKEN in (d / '.terraform/terraform.tfstate').read_text():
        raise RuntimeError('Credential persisted by backend')


def pull(d):
    raw = tf(d, d.name + '-state', ['state', 'pull'])[0]
    if TOKEN in raw:
        raise RuntimeError('Credential in state')
    value = json.loads(raw)
    for r in value.get('resources', []):
        if (r['type'], r['name']) not in [('kubernetes_config_map_v1', 'environment'), ('terraform_data', 'coordination_probe')]:
            raise RuntimeError('Foreign state preserved')
    return raw, value


def inspect_preview(value):
    changes = value.get('resource_changes', [])
    addresses = {'kubernetes_namespace_v1.lab', 'kubernetes_resource_quota_v1.budget', ADDRESS}
    if len(changes) != 3 or {x['address'] for x in changes} != addresses or any(x['change']['actions'] != ['create'] for x in changes):
        raise RuntimeError('Unexpected isolated preview')
    after = {x['address']: x['change']['after'] for x in changes}
    ns = after['kubernetes_namespace_v1.lab']['metadata'][0]
    quota = after['kubernetes_resource_quota_v1.budget']
    cm = after[ADDRESS]
    if ns['name'] != 'tf-devops-lab' or ns['labels'].get('petclinic.devops.local/owner') != 'terraform-iac-lab':
        raise RuntimeError('Wrong preview namespace')
    for resource, name in [(quota, 'lab-budget'), (cm, 'environment-manifest')]:
        if resource['metadata'][0]['name'] != name or resource['metadata'][0]['namespace'] != 'tf-devops-lab':
            raise RuntimeError('Wrong preview resource scope')
    hard = quota['spec'][0]['hard']
    if any(hard.get(k) != '0' for k in ['pods', 'persistentvolumeclaims', 'secrets', 'services', 'requests.storage']) or hard.get('configmaps') != '4':
        raise RuntimeError('Preview resource budget changed')
    if cm['data'] != {'config_revision': 'v1', 'managed_by': 'terraform', 'scenario': 'petclinic-devops-study'}:
        raise RuntimeError('Preview payload changed')
    return changes


def plan_only():
    d = directory('plan', 'plan')
    initialize(d)
    tf(d, 'preview', ['plan', '-refresh=false', '-input=false', '-no-color', '-detailed-exitcode', '-out=preview.tfplan'], (2,))
    value = json.loads(tf(d, 'show', ['show', '-json', 'preview.tfplan'])[0])
    changes = inspect_preview(value)
    return {'mode': 'plan', 'apply_executed': False, 'plan_changes': [{'address': x['address'], 'actions': x['change']['actions']} for x in changes]}


def shared():
    state_status, existing = api('GET', f'/api/v1/namespaces/{STORE}/secrets/{SECRET}')
    cm_status, cm_before = api('GET', f'/api/v1/namespaces/{LAB}/configmaps/environment-manifest')
    if state_status not in [200, 404] or cm_status not in [200, 404]:
        raise RuntimeError('Cannot verify existing state/resources')
    if state_status == 200 and existing['metadata'].get('labels', {}).get('petclinic.devops.local/owner') != OWNER:
        raise RuntimeError('Foreign state preserved')
    if cm_status == 200 and (state_status != 200 or cm_before['metadata'].get('labels', {}).get('petclinic.devops.local/owner') != OWNER):
        raise RuntimeError('Untracked ConfigMap preserved')
    a, b = directory('a', 'shared'), directory('b', 'shared')
    for d in [a, b]:
        (d / 'probe.auto.tfvars.json').write_text('{"coordination_probe":true}')
        initialize(d)
    missing = tf(b, 'missing-token', ['state', 'pull'], (1,), token='')[1]
    if not any(x in missing.lower() for x in ['forbidden', 'unauthorized']):
        raise RuntimeError('Missing token did not fail authentication')
    before_raw, before = pull(a)
    if any(x['type'] == 'terraform_data' for x in before.get('resources', [])):
        raise RuntimeError('Prior incomplete probe preserved')
    tf(a, 'plan', ['plan', '-input=false', '-parallelism=1', '-no-color', '-detailed-exitcode', '-out=run.tfplan'], (2,))
    changes = inspect_plan(json.loads(tf(a, 'show', ['show', '-json', 'run.tfplan'])[0]))
    writer = subprocess.Popen([BIN, 'apply', '-input=false', '-parallelism=1', '-no-color', 'run.tfplan'], cwd=a, env=make_environment(a, TOKEN), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    ACTIVE.append(writer)
    lease_path = f'/apis/coordination.k8s.io/v1/namespaces/{STORE}/leases/{LEASE}'
    lock = None
    try:
        for _ in range(80):
            _, current = api('GET', lease_path)
            if current.get('spec', {}).get('holderIdentity'):
                lock = current
                break
            if writer.poll() is not None:
                break
            time.sleep(0.1)
        if not lock:
            raise RuntimeError('No real writer lock observed')
        blocked = tf(b, 'lock-conflict', ['plan', '-input=false', '-no-color', '-lock-timeout=1s'], (1,))[1]
        lock_id = lock['spec']['holderIdentity']
        if 'Error acquiring the state lock' not in blocked or lock_id not in blocked:
            raise RuntimeError('Peer was not rejected for this lock')
        held = require_api('GET', lease_path)
        if held['metadata']['uid'] != lock['metadata']['uid'] or held['spec'].get('holderIdentity') != lock_id:
            raise RuntimeError('Writer lock changed')
        out, err = writer.communicate(timeout=60)
        (a / 'writer.log').write_text((out + err).replace(TOKEN, '[REDACTED]'))
        if writer.returncode:
            raise RuntimeError('Writer failed')
    finally:
        if writer.poll() is None:
            os.killpg(writer.pid, signal.SIGINT)
            writer.wait(timeout=8)
        ACTIVE.remove(writer)
    tf(b, 'repeat', ['plan', '-input=false', '-no-color', '-detailed-exitcode'], (0,))
    raw_a, state_a = pull(a)
    raw_b, state_b = pull(b)
    if raw_a != raw_b or state_a['lineage'] != before['lineage']:
        raise RuntimeError('Peer state differs')
    for d in [a, b]:
        (d / 'probe.auto.tfvars.json').write_text('{"coordination_probe":false}')
    tf(a, 'cleanup-plan', ['plan', '-input=false', '-no-color', '-detailed-exitcode', '-out=cleanup.tfplan'], (2,))
    inspect_plan(json.loads(tf(a, 'cleanup-show', ['show', '-json', 'cleanup.tfplan'])[0]), cleanup=True)
    tf(a, 'cleanup-probe', ['apply', '-input=false', '-no-color', 'cleanup.tfplan'])
    tf(b, 'final-repeat', ['plan', '-input=false', '-no-color', '-detailed-exitcode'], (0,))
    raw, final = pull(a)
    if pull(b)[0] != raw or len(final['resources']) != 1 or final['resources'][0]['type'] != 'kubernetes_config_map_v1':
        raise RuntimeError('Unexpected final shared state')
    if require_api('GET', lease_path).get('spec', {}).get('holderIdentity'):
        raise RuntimeError('State lock not released')
    name = 'tfstate-latest-success-petclinic-remote-v1'
    url = f'/api/v1/namespaces/{STORE}/secrets/{name}'
    status, old = api('GET', url)
    if status not in [200, 404] or status == 200 and old['metadata'].get('labels', {}).get('petclinic.devops.local/owner') != OWNER:
        raise RuntimeError('Foreign snapshot preserved')
    snapshot = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': STORE, 'labels': {'petclinic.devops.local/owner': OWNER}, **({'resourceVersion': old['metadata']['resourceVersion']} if status == 200 else {})}, 'type': 'Opaque', 'data': {'snapshot.gz': base64.b64encode(gzip.compress(raw.encode())).decode()}}
    if status == 404:
        require_api('POST', f'/api/v1/namespaces/{STORE}/secrets', snapshot, 201)
    else:
        require_api('PUT', url, snapshot)
    restored = gzip.decompress(base64.b64decode(require_api('GET', url)['data']['snapshot.gz'])).decode()
    if restored != raw:
        raise RuntimeError('Snapshot readback differs')
    _, cm = api('GET', f'/api/v1/namespaces/{LAB}/configmaps/environment-manifest')
    state_secret = require_api('GET', f'/api/v1/namespaces/{STORE}/secrets/{SECRET}')
    if state_status == 200 and state_secret['metadata']['uid'] != existing['metadata']['uid']:
        raise RuntimeError('State Secret replaced')
    if cm_status == 200 and cm['metadata']['uid'] != cm_before['metadata']['uid']:
        raise RuntimeError('ConfigMap replaced')
    return {'mode': 'shared', 'backend': 'kubernetes', 'state_secret_uid': state_secret['metadata']['uid'],
            'state_lineage': final['lineage'], 'state_serial': final['serial'], 'state_sha256': sha(raw.encode()),
            'config_map_uid': cm['metadata']['uid'], 'plan_changes': changes, 'peer_repeat_exit': 0, 'final_repeat_exit': 0,
            'missing_token_exit': 1, 'lock_contention': {'holder_id': lock_id, 'lease_uid': lock['metadata']['uid'], 'peer_exit': 1},
            'backend_lock_released': True, 'probe_removed': True, 'snapshot_secret': name, 'snapshot_verified': True,
            'credentials_absent_from_state': True}


def main():
    global TOKEN
    os.umask(0o077)
    WORK.mkdir(exist_ok=True)
    (WORK / 'tmp').mkdir(exist_ok=True)
    runtime = enforce()
    isolation = probe_isolation(runtime)
    signal.signal(signal.SIGTERM, stop_children)
    signal.signal(signal.SIGINT, stop_children)
    endpoint = urllib.parse.urlparse(os.environ['API_SERVER'])
    ipaddress.IPv4Address(endpoint.hostname)
    if endpoint.scheme != 'https' or endpoint.port != 6443:
        raise RuntimeError('Only numeric TLS API endpoint6443 allowed')
    TOKEN = Path('/var/run/terraform-identity/token').read_text().strip()
    payload = json.loads(base64.urlsafe_b64decode(TOKEN.split('.')[1] + '==='))
    if payload['sub'] != f'system:serviceaccount:{EXEC}:terraform-runner':
        raise RuntimeError('Wrong runtime identity')
    if not 120 < payload['exp'] - time.time() <= 1200:
        raise RuntimeError('Wrong token lifetime')
    forbidden = []
    for url in ['/api/v1/namespaces/ns-devops/secrets', '/api/v1/namespaces/petclinic/configmaps']:
        code, _ = api('GET', url)
        if code != 403:
            raise RuntimeError('Forbidden API access not rejected')
        forbidden.append({'path': url, 'http_status': code})
    permissions = []
    for ns, group, resource, verb in [(EXEC, 'batch', 'jobs', 'create'), (EXEC, '', 'pods', 'create'), ('ns-devops', '', 'pods/exec', 'create'), ('', '', 'namespaces', 'create')]:
        value = require_api('POST', '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', {'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SelfSubjectAccessReview', 'spec': {'resourceAttributes': {'namespace': ns, 'group': group, 'resource': resource, 'verb': verb}}}, 201)
        if value['status']['allowed']:
            raise RuntimeError('Runtime has orchestration/admin privileges')
        permissions.append({'namespace': ns, 'resource': resource, 'verb': verb, 'allowed': False})
    mode = os.environ['EXECUTION_MODE']
    if mode not in ['plan', 'shared', 'failure', 'deadline']:
        raise RuntimeError('Invalid execution mode')
    if mode == 'failure':
        print('TF_ISOLATION_REPORT:' + json.dumps({'status': 'expected-failure', 'isolation': isolation, 'before_state_write': True}), flush=True)
        return 42
    if mode == 'deadline':
        print('TF_ISOLATION_HOLD_READY', flush=True)
        time.sleep(120)
        raise RuntimeError('Deadline did not stop Job')
    result = plan_only() if mode == 'plan' else shared()
    result.update({'status': 'success', 'isolation': isolation, 'source': (SOURCE / '.git-sha').read_text().strip(),
                   'identity': payload['sub'], 'token_expires_at': payload['exp'], 'forbidden_reads': forbidden,
                   'permissions': permissions, 'records': RECORDS, 'pod': socket.gethostname(),
                   'memory_peak_bytes': int(Path('/sys/fs/cgroup/memory.peak').read_text()),
                   'cpu_stat': Path('/sys/fs/cgroup/cpu.stat').read_text()})
    print('TF_ISOLATION_REPORT:' + json.dumps(result), flush=True)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print('TF_ISOLATION_ERROR:' + str(error).replace(TOKEN, '[REDACTED]') if TOKEN else 'TF_ISOLATION_ERROR:' + str(error), flush=True)
        sys.exit(1)
