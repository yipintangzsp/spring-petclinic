"""Root-owned fixed SSH entry for Kyverno V2 admission probes.
No caller-provided image, namespace, policy or kubectl arguments: the caller
supplies only a code-owned project id, a run id and a code-owned case id.
Each case performs a server dry-run admission evaluation against the live
cluster Kyverno policies; the signed positive case additionally performs a
real create + delete of its Pod and verifies cleanup.
"""
import os, sys, json, pathlib, hashlib, subprocess, time, re, fcntl, signal, datetime

ROOT = pathlib.Path('/var/lib/security-kyverno')
KUBECTL = '/usr/local/bin/kubectl'
STAGES = []
CHILD = {'p': None}

def _term(signum, frame):
    p = CHILD['p']
    if p is not None:
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
    raise RuntimeError('RUNNER_TERMINATED')

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''): h.update(b)
    return h.hexdigest()

def iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def main():
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    m = re.fullmatch(r'admit-v1 ([a-zA-Z0-9_.-]+) (web-[a-f0-9-]{36}) ([a-z][a-z0-9-]*)', command)
    if not m: raise RuntimeError('COMMAND_REJECTED')
    project, run, case_id = m.groups()
    cfg = json.loads((ROOT / 'projects.json').read_text())
    p = cfg['projects'].get(project)
    if not p: raise RuntimeError('PROJECT_NOT_AUTHORIZED')
    case = p['cases'].get(case_id)
    if not case: raise RuntimeError('CASE_NOT_AUTHORIZED')
    if os.getuid() != cfg['uid'] or os.getgid() != cfg['gid'] or os.getgroups() not in [[], [cfg['gid']]]:
        raise RuntimeError('IDENTITY_REJECTED')
    if not re.search(r'NoNewPrivs:\s+1', pathlib.Path('/proc/self/status').read_text()):
        raise RuntimeError('IDENTITY_REJECTED')
    for forbidden in ['/run/docker.sock', '/etc/rancher/k3s/k3s.yaml']:
        if os.access(forbidden, os.R_OK): raise RuntimeError('PRODUCTION_AUTHORITY_READABLE')
    if sha(KUBECTL) != cfg['toolSha256']: raise RuntimeError('TOOL_DIGEST_REJECTED')
    import shutil
    mem = next(int(s.split()[1]) * 1024 for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:'))
    if mem < 512 * 1024**2 or shutil.disk_usage(ROOT).free < 2 * 1024**3 or os.getloadavg()[0] > os.cpu_count() * 0.9:
        raise RuntimeError('RESOURCE_BUDGET_BLOCKED')
    kubeconfig = str(ROOT / 'kubeconfig.yaml')
    kc = pathlib.Path(kubeconfig)
    st = kc.lstat()
    if not kc.is_file() or kc.is_symlink() or st.st_uid != cfg['uid'] or (st.st_mode & 0o077):
        raise RuntimeError('KUBECONFIG_REJECTED')
    lock = open(ROOT / 'data/execution.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    work = ROOT / 'data' / run
    work.mkdir(mode=0o700)
    stages = STAGES
    def stage(name, **kw):
        stages.append({'runId': run, 'stage': name, 'at': iso(), **kw})
        tmp = work / 'stages.tmp'; tmp.write_text(json.dumps(stages)); os.replace(tmp, work / 'stages.json')
    started = iso()
    stage('SOURCE_READY')
    pod = dict(case['pod'])
    suffix = run.replace('web-', '')[:8]
    pod_name = 'kyv-%s-%s' % (case_id, suffix)
    pod['metadata']['name'] = pod_name
    pod['metadata']['namespace'] = p['namespace']
    podfile = work / 'pod.json'
    podfile.write_text(json.dumps(pod))
    signal.signal(signal.SIGTERM, _term); signal.signal(signal.SIGHUP, _term)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT / 'data'), 'TMPDIR': str(work), 'LANG': 'C'}

    def kubectl(args, timeout=55):
        argv = [KUBECTL, '--kubeconfig', kubeconfig] + args
        child = subprocess.Popen(argv, cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, text=True)
        CHILD['p'] = child
        try: out, err = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL); child.wait(); raise RuntimeError('RUNNER_TIMEOUT')
        return child.returncode, out, err, child.pid

    stage('ADMISSION_START_ATTEMPT')
    rc, out, err, pid = kubectl(['create', '--dry-run=server', '-f', str(podfile), '-o', 'name'])
    stage('ADMISSION_STARTED', pid=pid)
    stage('ADMISSION_EXITED', exitCode=rc)
    allowed = (rc == 0)
    diagnostic = ('' if allowed else err.strip())[:1500]
    real = None
    cleanup = 'DRY_RUN_ONLY'
    if case.get('realCreate') and allowed:
        rc2, out2, err2, _pid2 = kubectl(['create', '-f', str(podfile), '-o', 'name'])
        created = (rc2 == 0)
        stage('REAL_CREATE_EXITED', exitCode=rc2)
        deleted = False; gone = False
        if created:
            rc3, out3, err3, _pid3 = kubectl(['delete', 'pod', pod_name, '-n', p['namespace'], '--ignore-not-found', '--force', '--grace-period=0'], timeout=30)
            deleted = (rc3 == 0)
            rc4, out4, err4, _pid4 = kubectl(['get', 'pod', pod_name, '-n', p['namespace'], '-o', 'name'])
            gone = (rc4 != 0)
        real = {'attempted': True, 'created': created, 'deleted': deleted, 'verifiedGone': gone}
        cleanup = 'VERIFIED' if (created and deleted and gone) else 'INCOMPLETE'
        if cleanup != 'VERIFIED': raise RuntimeError('RUNNER_CLEANUP_FAILED')
    else:
        cleanup = 'VERIFIED'
    stage('RUN_COMPLETED')
    print(json.dumps({'kind': 'RestrictedLinuxKyverno', 'projectId': project, 'runId': run, 'caseId': case_id,
                      'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(), 'noNewPrivs': True,
                      'namespace': p['namespace'], 'policy': p['policy'], 'image': case['image'],
                      'allowed': allowed, 'exitCode': rc, 'diagnostic': diagnostic,
                      'toolVersion': cfg['toolVersion'], 'toolSha256': cfg['toolSha256'],
                      'startedAt': started, 'completedAt': iso(), 'stages': stages,
                      'realCreate': real, 'cleanup': cleanup}))

try: main()
except Exception as e:
    code = str(e) if re.fullmatch('[A-Z_]{3,80}', str(e)) else 'EXECUTION_REJECTED'
    try: print(json.dumps({'error': code, 'stages': STAGES}))
    except Exception: pass
    sys.exit(1)
