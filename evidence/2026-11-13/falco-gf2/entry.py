"""Root-owned fixed SSH entry for the Falco V2 collector (G-F2).

Single forced command: collect-v1 <projectId> <windowEndMs>. The caller
(zhang's devops-local V2 driver identity) supplies only a code-owned project
id and the observation window end; every kubectl operation, namespace, label,
daemonset and node name comes from the root-owned pinned config beside this
file (entry-projects.json). All cluster access uses the dedicated
least-privilege ServiceAccount kubeconfig owned by security-falco
(uid/gid 1007); this identity has no sudo, no shell use (forced command),
and no access to the host's admin kubeconfig. The packet returned is exactly
the observation set the previous sudo-kubectl collector produced: sensor pod
listing, DaemonSet, node, workload pod listing, three Falco log slices and
the sensor healthz result.
"""
import os, sys, json, pathlib, hashlib, subprocess, re, fcntl, urllib.request, urllib.error, datetime

ROOT = pathlib.Path('/var/lib/security-falco')
KUBECTL = '/usr/local/bin/kubectl'
KUBECONFIG = ROOT / 'kubeconfig.yaml'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def iso(ms):
    dt = datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{ms % 1000:03d}Z'


def fail():
    print(json.dumps({'error': 'RUNNER_ERROR'}))
    sys.exit(1)


def main():
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    m = re.fullmatch(r'collect-v1 ([a-z][a-z0-9-]*) ([0-9]{13})', command)
    if not m:
        raise RuntimeError('COMMAND_REJECTED')
    project_id, window_end_ms = m.group(1), int(m.group(2))
    cfg = json.loads((ROOT / 'entry-projects.json').read_text())
    project = cfg['projects'].get(project_id)
    if not project:
        raise RuntimeError('PROJECT_NOT_AUTHORIZED')
    if os.getuid() != cfg['uid'] or os.getgid() != cfg['gid'] or os.getgroups() not in ([], [cfg['gid']]):
        raise RuntimeError('IDENTITY_REJECTED')
    if not re.search(r'NoNewPrivs:\s+1', pathlib.Path('/proc/self/status').read_text()):
        raise RuntimeError('IDENTITY_REJECTED')
    for forbidden in ['/etc/rancher/k3s/k3s.yaml', '/run/docker.sock']:
        if os.access(forbidden, os.R_OK):
            raise RuntimeError('PRODUCTION_AUTHORITY_READABLE')
    if sha(os.path.realpath(KUBECTL)) != cfg['kubectlSha256']:
        raise RuntimeError('TOOL_DIGEST_REJECTED')
    st = KUBECONFIG.lstat()
    if KUBECONFIG.is_symlink() or not KUBECONFIG.is_file() or st.st_uid != cfg['uid'] or (st.st_mode & 0o077):
        raise RuntimeError('KUBECONFIG_REJECTED')
    now_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    if abs(now_ms - window_end_ms) > 3600000:
        raise RuntimeError('WINDOW_REJECTED')
    lockf = open(ROOT / 'data/execution.lock', 'a')
    fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(ROOT), 'LANG': 'C'}

    def kubectl(args):
        argv = [KUBECTL, '--kubeconfig', str(KUBECONFIG), '--request-timeout=15s'] + args
        r = subprocess.run(argv, capture_output=True, text=True, timeout=25, env=env)
        if r.returncode != 0:
            raise RuntimeError('RUNNER_ERROR')
        return {'status': 0, 'stdout': r.stdout}

    ns = project['sensorNamespace']
    label = project['sensorPodLabel']
    sensor_pods = kubectl(['-n', ns, 'get', 'pods', '-l', label, '-o', 'json'])
    try:
        items = [p for p in json.loads(sensor_pods['stdout']).get('items', []) if not p.get('metadata', {}).get('deletionTimestamp')]
    except Exception:
        raise RuntimeError('RUNNER_ERROR')
    if len(items) != 1:
        raise RuntimeError('RUNNER_ERROR')
    pod = items[0]
    pod_name = pod.get('metadata', {}).get('name', '')
    pod_ip = pod.get('status', {}).get('podIP', '')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,60}', pod_name or '') or not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', pod_ip or ''):
        raise RuntimeError('RUNNER_ERROR')
    window_start_ms = window_end_ms - 15000
    full_since_ms = window_end_ms - 180000
    ds = kubectl(['-n', ns, 'get', 'ds', project['sensorDaemonSet'], '-o', 'json'])
    node = kubectl(['get', 'node', project['node'], '-o', 'json'])
    workloads = kubectl(['-n', project['workloadNamespace'], 'get', 'pods', '-o', 'json'])
    diagnostic_log = kubectl(['-n', ns, 'logs', pod_name, '-c', 'falco', '--tail=500'])
    sample_log = kubectl(['-n', ns, 'logs', pod_name, '-c', 'falco', '--since-time=' + iso(window_start_ms), '--tail=1000'])
    full_log = kubectl(['-n', ns, 'logs', pod_name, '-c', 'falco', '--since-time=' + iso(full_since_ms), '--tail=1000'])
    try:
        with urllib.request.urlopen('http://' + pod_ip + ':8765/healthz', timeout=5) as r:
            health = {'ok': r.status == 200, 'status': r.status} if r.status == 200 else {'ok': False, 'error': 'HTTP_' + str(r.status)}
    except urllib.error.HTTPError as e:
        health = {'ok': False, 'error': 'HTTP_' + str(e.code)}
    except Exception:
        health = {'ok': False, 'error': 'HEALTHZ_UNREACHABLE'}
    packet = {
        'kind': 'FalcoCollectorPacket',
        'projectId': project_id,
        'windowEndMs': window_end_ms,
        'identity': {
            'user': 'security-falco', 'uid': os.getuid(), 'gid': os.getgid(),
            'serviceAccount': project['serviceAccount'],
            'serviceAccountNamespace': project['serviceAccountNamespace'],
            'kubeconfig': str(KUBECONFIG),
        },
        'results': {
            'ds': ds, 'sensorPods': sensor_pods, 'node': node, 'workloads': workloads,
            'diagnosticLog': diagnostic_log, 'sampleLog': sample_log, 'fullLog': full_log,
        },
        'health': health,
    }
    print(json.dumps(packet))


try:
    main()
except RuntimeError as e:
    msg = str(e)
    if msg in ('RUNNER_ERROR',):
        fail()
    print(json.dumps({'error': msg}))
    sys.exit(1)
