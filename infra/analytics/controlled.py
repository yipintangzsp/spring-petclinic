"""Shared resource admission and monitoring for one manual analytics run at a time."""
import datetime as dt
import fcntl
import json
import inspect
import os
from clinic_task import cpu_request_milli, pod_cpu_request_milli, disk_required_mib
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path

HOST = '192.168.1.58'
NAMESPACE = 'data-infra'
LEASE = 'platform-heavy'
RESERVE_MIB = 1250


def remote(command, body=None, timeout=30):
    options = []
    address = os.environ.get('PETCLINIC_SSH_ADDRESS')
    if address:
        options = ['-o', f'HostName={address}', '-o', f'HostKeyAlias={HOST}']
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
                             *options, HOST, command], input=body, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr[-1000:])
    return result.stdout


def kube(arguments, resource=None, timeout=30):
    output = remote(shlex.join(['sudo', '-n', 'kubectl', '--request-timeout=10s', *arguments]),
                    None if resource is None else json.dumps(resource), timeout)
    try:
        return json.loads(output) if output.strip().startswith(('{', '[')) else output.strip()
    except json.JSONDecodeError:
        # JSON-lines logs are text; only a complete JSON response is an object.
        return output.strip()


JENKINS_REQUEST = r"""const fs=require('fs');(async()=>{
 const i=JSON.parse(fs.readFileSync(0,'utf8'));const base=process.env.JENKINS_URL;
 const h={Authorization:'Basic '+Buffer.from(process.env.JENKINS_USER+':'+process.env.JENKINS_PASS).toString('base64')};
 if(i.method==='POST'){
  const r=await fetch(base+'/crumbIssuer/api/json',{headers:h,signal:AbortSignal.timeout(8000)});if(!r.ok)throw Error('Crumb HTTP '+r.status);
  const c=await r.json();h[c.crumbRequestField]=c.crumb;h.Cookie=r.headers.getSetCookie().map(x=>x.split(';')[0]).join('; ');
 }
 const r=await fetch(base+i.path,{method:i.method,headers:h,signal:AbortSignal.timeout(12000)});
 if(!r.ok)throw Error('Jenkins HTTP '+r.status);const body=await r.text();console.log(JSON.stringify({status:r.status,body}));
})().catch(e=>{console.error(e.message);process.exit(1)});"""


def jenkins(path, method='GET'):
    allowed = ['/api/json?tree=quietingDown,jobs[name,lastBuild[building]]',
               '/quietDown', '/cancelQuietDown']
    if path not in allowed:
        raise ValueError('Only resource concurrency operations are supported')
    command = shlex.join(['sudo', '-n', 'kubectl', 'exec', '-i', '-n', 'ns-devops',
                          'deploy/github-webhook-relay', '--', 'node', '--max-old-space-size=24', '-e', JENKINS_REQUEST])
    lock_dir = Path.home() / '.codex' / 'locks'
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    with (lock_dir / 'petclinic-jenkins-relay.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = json.loads(remote(command, json.dumps({'path': path, 'method': method}), timeout=40))
    return json.loads(result['body']) if result['body'].strip().startswith('{') else result['status']


SAMPLE_CODE = inspect.getsource(cpu_request_milli) + '\n' + inspect.getsource(pod_cpu_request_milli) + '\n' + r'''import json,pathlib,subprocess,time
mem={l.split(':')[0]:int(l.split()[1]) for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if len(l.split())>1 and l.split()[1].isdigit()}
result={'at':time.time(),'availableMiB':mem['MemAvailable']/1024,'swapUsedMiB':(mem['SwapTotal']-mem['SwapFree'])/1024,'pressure':{},'http':{}}
for kind in ['memory','io','cpu']:
 result['pressure'][kind]={line.split()[0]:{v.split('=')[0]:float(v.split('=')[1]) for v in line.split()[1:]} for line in pathlib.Path('/proc/pressure/'+kind).read_text().splitlines()}
for name,host,path in [('petclinic','petclinic.devops.local','/actuator/health/readiness'),('cook','cook.devops.local','/'),('database','petclinic.devops.local','/actuator/health')]:
 p=subprocess.run(['curl','--noproxy','*','-sS','--max-time','4','-H','Host: '+host,'-o','/dev/null','-w','%{http_code} %{time_total}','http://192.168.1.58'+path],capture_output=True,text=True,timeout=5);result['http'][name]={'value':p.stdout,'exit':p.returncode}
p=subprocess.run(['kubectl','--request-timeout=5s','get','--raw=/readyz'],capture_output=True,text=True,timeout=6);result['apiReady']=p.returncode==0 and p.stdout.strip()=='ok'
p=subprocess.run(['kubectl','--request-timeout=5s','get','nodes','-o','json'],capture_output=True,text=True,timeout=6);nodes=json.loads(p.stdout)['items'];node=next(n for n in nodes if n['metadata']['name']=='devops');result['conditions']=node['status']['conditions']
p=subprocess.run(['kubectl','--request-timeout=5s','get','pods','-A','-o','json'],capture_output=True,text=True,timeout=6);pods=json.loads(p.stdout)['items'];result['failures']=[];result['resources']=[]
result['cpuAllocatableMilli']=cpu_request_milli(node['status']['allocatable']['cpu'])
result['cpuRequestedMilli']=sum(pod_cpu_request_milli(pod) for pod in pods if pod['spec'].get('nodeName')=='devops' and pod['status'].get('phase') not in ['Succeeded','Failed'])
for pod in pods:
 if pod['spec'].get('nodeName')!='devops':continue
 for c in pod['status'].get('containerStatuses',[]):
  term=c.get('lastState',{}).get('terminated',{});current=c.get('state',{}).get('terminated',{})
  if 'OOMKilled' in [term.get('reason'),current.get('reason')]:result['failures'].append([pod['metadata']['uid'],c['name'],c['restartCount'],'OOMKilled'])
 if pod['status'].get('reason')=='Evicted':result['failures'].append([pod['metadata']['uid'],'pod',0,'Evicted'])
 if pod['metadata'].get('labels',{}).get('app')=='petclinic-analysis' or 'airflow' in pod['metadata']['name'] or 'spark' in pod['metadata']['name'] or 'flink' in pod['metadata']['name']:
  result['resources'].append({'name':pod['metadata']['name'],'namespace':pod['metadata']['namespace'],'phase':pod['status']['phase'],'containers':[{'name':c['name'],'resources':c.get('resources',{})} for c in pod['spec']['containers']]})
p=subprocess.run(['df','-Pk','/'],capture_output=True,text=True,timeout=3);row=p.stdout.splitlines()[-1].split();result['diskFreeMiB']=int(row[3])/1024;result['diskCapacityMiB']=int(row[1])/1024
print(json.dumps(result))'''


def sample():
    value = json.loads(remote('sudo -n python3 -c ' + shlex.quote(SAMPLE_CODE), timeout=40))
    if Path('/usr/bin/memory_pressure').exists():
        pressure = subprocess.check_output(['/usr/bin/memory_pressure', '-Q'], text=True, timeout=5)
        swap = subprocess.check_output(['/usr/sbin/sysctl', 'vm.swapusage'], text=True, timeout=5)
        disk = subprocess.check_output(['df', '-Pk', '/System/Volumes/Data'], text=True, timeout=5)
        value['mac'] = {'freePercent': int(re.search(r'free percentage: (\d+)%', pressure).group(1)),
                        'swapUsedMiB': float(re.search(r'used = ([0-9.]+)M', swap).group(1)),
                        'diskFreeMiB': int(disk.splitlines()[-1].split()[3]) / 1024}
        efi = Path.home() / 'Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm/Data/efi_vars.fd'
        value['mac']['efiAllocatedMiB'] = efi.stat().st_blocks / 2048 if efi.exists() else None
    return value


def blockers(value, bad_http=0, previous_failures=()):
    reasons = []
    if value.get('mac', {}).get('freePercent', 100) < 10:
        reasons.append('Mac memory free percentage below 10')
    if value.get('mac', {}).get('diskFreeMiB', 0) < 16384:
        reasons.append('Mac data filesystem has less than 16 GiB free')
    efi = value.get('mac', {}).get('efiAllocatedMiB')
    if efi is None or efi > 128:
        reasons.append('UTM EFI allocation missing or above 128 MiB; inspect saved memory snapshots')
    if value['availableMiB'] < 1536:
        reasons.append('MemAvailable below 1536 MiB')
    if value['diskFreeMiB'] < disk_required_mib(value.get('diskCapacityMiB')):
        reasons.append('Root filesystem requires 15 percent free plus 8 GiB task allowance')
    if value['pressure']['memory']['full']['avg10'] > 5:
        reasons.append('Memory full PSI avg10 exceeds 5')
    if value['pressure']['io']['full']['avg10'] > 10:
        reasons.append('I/O full PSI avg10 exceeds 10')
    if any(c['type'].endswith('Pressure') and c['status'] != 'False' for c in value['conditions']):
        reasons.append('Local node pressure')
    if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in value['conditions']):
        reasons.append('Local node is not Ready')
    if bad_http >= 3:
        reasons.append('Three consecutive business/API failures')
    if set(map(tuple, value['failures'])) - set(map(tuple, previous_failures)):
        reasons.append('New OOMKilled or Evicted workload')
    return reasons


def http_bad(value):
    if not value['apiReady']:
        return True
    for name, record in value['http'].items():
        pieces = record['value'].split()
        if record['exit'] or len(pieces) != 2 or pieces[0] != '200':
            return True
        if float(pieces[1]) > (1 if name == 'cook' else 2):
            return True
    return False


class HeavyRun:
    """Use with a finally block which stops the owned compute before releasing the Lease."""
    def __init__(self, task, budget_mib, evidence):
        self.holder = task + '-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')
        if not isinstance(budget_mib, int) or not 256 <= budget_mib <= 16384:
            raise ValueError("A measured full-process budget of 256–16384 MiB is required")
        self.budget = budget_mib
        self.evidence = Path(evidence)
        self.stop = threading.Event()
        self.failure = None
        self.samples = []
        self.initial_failures = []
        self.owned_quiet = False
        self.compute_stopped = True

    def __enter__(self):
        before = sample()
        reasons = blockers(before, previous_failures=before['failures'])
        if http_bad(before):
            reasons.append('Business/API baseline is unhealthy')
        if before['availableMiB'] < self.budget + RESERVE_MIB:
            reasons.append(f'Require {self.budget + RESERVE_MIB} MiB including reserve')
        if reasons:
            raise RuntimeError('; '.join(reasons))
        stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
        obj = {'apiVersion': 'coordination.k8s.io/v1', 'kind': 'Lease',
               'metadata': {'name': LEASE, 'namespace': NAMESPACE,
                            'annotations': {'petclinic.devops.local/budget-mib': str(self.budget)}},
               'spec': {'holderIdentity': self.holder, 'acquireTime': stamp,
                        'renewTime': stamp, 'leaseDurationSeconds': 3600}}
        self.lease = kube(['create', '-f', '-', '-o', 'json'], obj)
        # Pause new Jenkins dispatches while preserving queued work. One small relay
        # request at a time; credentials never leave the existing relay environment.
        try:
            state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
            if not state.get('quietingDown'):
                jenkins('/quietDown', 'POST')
                self.owned_quiet = True
            state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
            if any(j.get('lastBuild', {}).get('building') for j in state['jobs'] if j.get('lastBuild')):
                raise RuntimeError('Wait for the active Jenkins build to finish')
        except Exception:
            kube(['-n', NAMESPACE, 'delete', 'lease', LEASE, '--wait=false'])
            if self.owned_quiet:
                jenkins('/cancelQuietDown', 'POST')
            raise
        self.initial_failures = before['failures']
        self.samples.append(before)
        self.thread = threading.Thread(target=self._watch, daemon=True)
        self.thread.start()
        return self

    def _watch(self):
        bad = 0
        while not self.stop.wait(15):
            try:
                value = sample()
                self.samples.append(value)
                bad = bad + 1 if http_bad(value) else 0
                reasons = blockers(value, bad, self.initial_failures)
                if value.get('mac', {}).get('swapUsedMiB', 0) - self.samples[0].get('mac', {}).get('swapUsedMiB', 0) > 512:
                    reasons.append('Mac swap grew by more than 512 MiB')
                if reasons:
                    self.failure = '; '.join(reasons)
                    return
                now = dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
                kube(['-n', NAMESPACE, 'patch', 'lease', LEASE, '--type=json', '-p',
                      json.dumps([{'op': 'test', 'path': '/metadata/uid', 'value': self.lease['metadata']['uid']},
                                  {'op': 'test', 'path': '/spec/holderIdentity', 'value': self.holder},
                                  {'op': 'replace', 'path': '/spec/renewTime', 'value': now}])])
            except Exception as error:
                self.failure = 'Monitoring failed: ' + str(error)
                return

    def check(self):
        if self.failure:
            raise RuntimeError('Safety stop: ' + self.failure)

    def __exit__(self, typ, value, traceback):
        self.stop.set()
        self.thread.join(timeout=50)
        self.evidence.mkdir(parents=True, exist_ok=True)
        (self.evidence / 'resource-samples.json').write_text(json.dumps({
            'holder': self.holder, 'budgetMiB': self.budget, 'reserveMiB': RESERVE_MIB,
            'safetyFailure': self.failure, 'samples': self.samples}, indent=2))
        if self.thread.is_alive():
            raise RuntimeError('Monitor has not stopped; preserve Lease and Jenkins quiet mode')
        if not self.compute_stopped:
            raise RuntimeError('Compute cleanup could not be confirmed; preserve Lease and Jenkins quiet mode')
        current = kube(['-n', NAMESPACE, 'get', 'lease', LEASE, '-o', 'json'])
        if current['metadata']['uid'] != self.lease['metadata']['uid'] or current['spec']['holderIdentity'] != self.holder:
            raise RuntimeError('Lease changed; preserve it for inspection')
        kube(['-n', NAMESPACE, 'delete', 'lease', LEASE, '--wait=false'])
        if self.owned_quiet:
            jenkins('/cancelQuietDown', 'POST')
