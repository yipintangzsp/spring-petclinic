"""Root-owned fixed SSH entry for Kubescape V2 cluster posture audits.
No caller-provided framework, namespace, target or kubectl arguments: the
caller supplies only a code-owned project id, a run id and a code-owned case
id. Each case executes the unchanged frozen governance audit
(infra/security/governance/kubescape.mjs) under its passive runtime-facts
observer, using the pinned Kubescape 4.0.17 binary and offline framework
artifacts, a dedicated least-privilege entry identity, and an outer
platform-heavy Lease held for the duration of the run. The violating case
additionally creates a known-bad Deployment in the isolated kubescape-v2-test
namespace before the audit and deletes it (verified) afterwards. The
short-lived kubescape-readonly token observed by the frozen adapter is
redacted to its SHA-256 before the packet leaves this host.
"""
import os, sys, json, pathlib, hashlib, subprocess, time, re, fcntl, signal, datetime, shutil

ROOT = pathlib.Path('/var/lib/security-kubescape')
KUBECTL = '/usr/local/bin/kubectl'
NODE = '/usr/bin/node'
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

def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()

def iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def micro():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

def main():
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    m = re.fullmatch(r'audit-v1 ([a-zA-Z0-9_.-]+) (web-[a-f0-9-]{36}) ([a-z][a-z0-9-]*)', command)
    if not m: raise RuntimeError('COMMAND_REJECTED')
    project, run, case_id = m.groups()
    cfg = json.loads((ROOT / 'entry-projects.json').read_text())
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
    if sha(KUBECTL) != cfg['kubectlSha256']: raise RuntimeError('TOOL_DIGEST_REJECTED')
    tool = cfg['tool']
    if sha(tool['binary']) != tool['binarySha256']: raise RuntimeError('TOOL_DIGEST_REJECTED')
    for name, want in tool['artifacts'].items():
        if sha(str(pathlib.Path(tool['artifactRoot']) / name)) != want: raise RuntimeError('TOOL_DIGEST_REJECTED')
    for rel, want in cfg['srcSha256'].items():
        if sha(str(ROOT / 'src' / rel)) != want: raise RuntimeError('SOURCE_DIGEST_REJECTED')
    mem = next(int(s.split()[1]) * 1024 for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:'))
    if mem < 2 * 1024**3 or shutil.disk_usage(ROOT).free < 2 * 1024**3 or os.getloadavg()[0] > os.cpu_count() * 0.9:
        raise RuntimeError('RESOURCE_BUDGET_BLOCKED')
    kubeconfig = str(ROOT / 'kubeconfig.yaml')
    kc = pathlib.Path(kubeconfig)
    st = kc.lstat()
    if not kc.is_file() or kc.is_symlink() or st.st_uid != cfg['uid'] or (st.st_mode & 0o077):
        raise RuntimeError('KUBECONFIG_REJECTED')
    lockf = open(ROOT / 'data/execution.lock', 'a')
    fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    work = ROOT / 'data' / run
    work.mkdir(mode=0o700)
    stages = STAGES
    def stage(name, **kw):
        stages.append({'runId': run, 'stage': name, 'at': iso(), **kw})
        tmp = work / 'stages.tmp'; tmp.write_text(json.dumps(stages)); os.replace(tmp, work / 'stages.json')
    started = iso()
    stage('SOURCE_READY')
    signal.signal(signal.SIGTERM, _term); signal.signal(signal.SIGHUP, _term)
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(work), 'TMPDIR': str(work), 'LANG': 'C'}
    def kubectl(args, timeout=55, inp=None):
        argv = [KUBECTL, '--kubeconfig', kubeconfig] + args
        child = subprocess.Popen(argv, cwd=work, env=env, stdin=subprocess.PIPE if inp is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, text=True)
        CHILD['p'] = child
        try: out, err = child.communicate(input=inp, timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL); child.wait(); raise RuntimeError('KUBECTL_TIMEOUT')
        return child.returncode, out, err
    holder = 'smv2-kubescape-' + run.replace('web-', '')[:8]
    lease_owned = False
    violating = None
    try:
        rc, out, err = kubectl(['-n', 'data-infra', 'get', 'lease', 'platform-heavy', '-o', 'json'])
        if rc == 0: raise RuntimeError('LEASE_HELD_BY_OTHER')
        lease = {'apiVersion': 'coordination.k8s.io/v1', 'kind': 'Lease', 'metadata': {'name': 'platform-heavy', 'namespace': 'data-infra', 'labels': {'app.kubernetes.io/part-of': 'petclinic-platform'}}, 'spec': {'holderIdentity': holder, 'acquireTime': micro(), 'renewTime': micro(), 'leaseDurationSeconds': 3600}}
        rc, out, err = kubectl(['create', '-f', '-'], inp=json.dumps(lease))
        if rc != 0: raise RuntimeError('LEASE_ACQUIRE_FAILED')
        lease_owned = True
        stage('LEASE_ACQUIRED', holder=holder)
        if case.get('violating'):
            dep = case['deployment']
            rc, out, err = kubectl(['-n', 'kubescape-v2-test', 'apply', '-f', '-'], inp=json.dumps(dep))
            if rc != 0: raise RuntimeError('VIOLATING_CREATE_FAILED')
            violating = {'namespace': 'kubescape-v2-test', 'deployment': dep['metadata']['name'], 'created': True, 'deleted': False, 'verifiedGone': False}
            stage('VIOLATING_CREATED', deployment=dep['metadata']['name'])
            time.sleep(3)
        repo = work / 'repo'
        shutil.copytree(ROOT / 'src', repo)
        lockdoc = json.loads((ROOT / 'tools-lock.repo.json').read_text())
        lockdoc['kubescape']['path'] = tool['binary']
        lockdoc['kubescape']['artifactRoot'] = tool['artifactRoot']
        (repo / 'infra/security/governance/tools-lock.json').write_text(json.dumps(lockdoc, indent=2))
        facts_path = work / 'facts.jsonl'
        gov_env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(work), 'TMPDIR': str(work), 'LANG': 'C', 'KUBECONFIG': kubeconfig, 'HEAVY_HOLDER': holder, 'RUNTIME_FACT_SOURCE': 'kubescape', 'NODE_OPTIONS': ''}
        cmd = 'exec 3>%s; exec %s --import %s %s' % (facts_path, NODE, repo / 'infra/security/runtime-facts/kubescape-observer.mjs', repo / 'infra/security/governance/kubescape.mjs')
        child = subprocess.Popen(['/bin/sh', '-c', cmd], cwd=repo, env=gov_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, text=True)
        CHILD['p'] = child
        stage('SCAN_STARTED', pid=child.pid)
        try: gout, gerr = child.communicate(timeout=1400)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL); child.wait(); raise RuntimeError('KUBESCAPE_EXECUTION_TIMEOUT')
        if child.returncode != 0: raise RuntimeError('KUBESCAPE_EXECUTION_FAILED')
        stage('SCAN_COMPLETED')
        lines = facts_path.read_text().splitlines()
        if len(lines) != 1: raise RuntimeError('RUNTIME_FACTS_MISSING')
        observed = json.loads(lines[0])
        if observed.get('sourceId') != 'kubescape' or observed.get('exitStatus') != 0: raise RuntimeError('RUNTIME_FACTS_INVALID')
        raw = observed['adapterPayload']
        tok = raw.get('observations', {}).get('token', {})
        if isinstance(tok.get('stdout'), str) and tok['stdout']:
            tok['stdout'] = 'REDACTED_SHA256:' + sha_bytes(tok['stdout'].encode())
        gate_doc = json.loads((repo / '.devsecops/kubescape-gate.json').read_text())
        gate = {'status': gate_doc.get('status'), 'findings': gate_doc.get('findings'), 'failedControls': gate_doc.get('failedControls'), 'highRiskFindings': gate_doc.get('highRiskFindings')}
        if gate['status'] != 'success': raise RuntimeError('KUBESCAPE_GATE_NOT_SUCCESS')
        if violating:
            name = violating['deployment']
            rc, out, err = kubectl(['-n', 'kubescape-v2-test', 'delete', 'deployment', name, '--wait=true'], timeout=90)
            if rc != 0: raise RuntimeError('VIOLATING_DELETE_FAILED')
            violating['deleted'] = True
            for _ in range(30):
                rc1, out1, _e1 = kubectl(['-n', 'kubescape-v2-test', 'get', 'pods', '-l', 'app=smv2-violating', '-o', 'name'])
                rc2, out2, _e2 = kubectl(['-n', 'kubescape-v2-test', 'get', 'deployment', name, '-o', 'name'])
                if rc1 == 0 and not out1.strip() and rc2 != 0:
                    violating['verifiedGone'] = True; break
                time.sleep(2)
            if not violating['verifiedGone']: raise RuntimeError('VIOLATING_CLEANUP_UNVERIFIED')
            stage('VIOLATING_DELETED', deployment=name)
        rc, out, err = kubectl(['-n', 'data-infra', 'get', 'lease', 'platform-heavy', '-o', 'json'])
        if rc == 0 and json.loads(out).get('spec', {}).get('holderIdentity') == holder:
            rc, out, err = kubectl(['-n', 'data-infra', 'delete', 'lease', 'platform-heavy', '--wait=true'])
            if rc != 0: raise RuntimeError('LEASE_RELEASE_FAILED')
            lease_owned = False
        elif rc == 0:
            raise RuntimeError('LEASE_HOLDER_CHANGED')
        stage('LEASE_RELEASED')
        stage('RUN_COMPLETED')
        packet = {'kind': 'RestrictedLinuxKubescape', 'projectId': project, 'runId': run, 'caseId': case_id, 'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(), 'noNewPrivs': True, 'toolVersion': tool['version'], 'toolSha256': tool['binarySha256'], 'exitCode': 0, 'cleanup': 'VERIFIED', 'gate': gate, 'stages': stages, 'startedAt': started, 'completedAt': iso(), 'raw': raw}
        if violating: packet['violating'] = violating
        shutil.rmtree(work, ignore_errors=True)
        print(json.dumps(packet))
    finally:
        if violating and not violating.get('verifiedGone'):
            try: kubectl(['-n', 'kubescape-v2-test', 'delete', 'deployment', violating['deployment'], '--wait=false'], timeout=30)
            except Exception: pass
        if lease_owned:
            try:
                rc, out, err = kubectl(['-n', 'data-infra', 'get', 'lease', 'platform-heavy', '-o', 'json'], timeout=30)
                if rc == 0 and json.loads(out).get('spec', {}).get('holderIdentity') == holder:
                    kubectl(['-n', 'data-infra', 'delete', 'lease', 'platform-heavy', '--wait=false'], timeout=30)
            except Exception: pass
        shutil.rmtree(work, ignore_errors=True)

if __name__ == '__main__':
    try:
        main()
    except RuntimeError as e:
        code = str(e) if re.fullmatch(r'[A-Z_0-9]+', str(e)) else 'ENTRY_ERROR'
        print(json.dumps({'error': code, 'stages': STAGES}))
        sys.exit(1)
    except Exception:
        print(json.dumps({'error': 'ENTRY_ERROR', 'stages': STAGES}))
        sys.exit(1)
