"""Root-owned, unprivileged forced command. No shell or caller-supplied paths."""
import os,sys,json,pathlib,subprocess,re,time,fcntl,resource,signal,hashlib
ROOT=pathlib.Path('/var/tmp/security-manager-gitleaks-cosign-web-20261106')
def reject(code):
 print(json.dumps({'error':code}),flush=True);raise SystemExit(2)
approval=json.loads((ROOT/'cosign-approval.json').read_text())
uid=approval['executionUid']
if os.getuid()!=uid or os.getgid()!=approval['executionGid'] or any(g!=approval['executionGid'] for g in os.getgroups()):reject('IDENTITY_REJECTED')
command=os.environ.get('SSH_ORIGINAL_COMMAND','')
m=re.fullmatch(r'(valid-v1|invalid-v1) (web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})',command)
if not m:reject('FIXED_COMMAND_REQUIRED')
finding=m[1]=='invalid-v1'
run=m[2]
# No input is part of this protocol; the client must close stdin.
import select
if not select.select([sys.stdin],[],[],2)[0] or sys.stdin.buffer.read(1):reject('INPUT_REJECTED')
for p in ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml','/root/.ssh','/home/zhang/.ssh','/home/zhang/.kube/config','/var/run/secrets/kubernetes.io/serviceaccount/token']:
 if os.access(p,os.R_OK):reject('PRODUCTION_AUTHORITY_READABLE')
def trusted(p):
 s=p.lstat()
 if p.resolve()!=p or s.st_uid!=0 or s.st_mode&0o022:reject('UNTRUSTED_RELEASE')
 return s
trusted(ROOT);trusted(ROOT/'package');trusted(ROOT/'cosign-approval.json')
manifest=ROOT/'package-manifest.json';trusted(manifest)
for name,h in json.loads(manifest.read_text()).items():
 p=ROOT/'package'/name
 if pathlib.PurePosixPath(name).is_absolute() or '..' in pathlib.PurePosixPath(name).parts:reject('RELEASE_PATH_REJECTED')
 trusted(p)
 if hashlib.sha256(p.read_bytes()).hexdigest()!=h:reject('RELEASE_CHANGED')
out=ROOT/'outputs';st=out.lstat()
if out.resolve()!=out or st.st_uid!=uid or st.st_mode&0o077:reject('OUTPUT_DOMAIN_REJECTED')
lock=open(out/'execution.lock','a')
try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:reject('EXECUTION_BUSY')
if (out/run).exists():reject('RUN_ALREADY_EXISTS')
if len(list(out.iterdir()))>=101:reject('OUTPUT_BUDGET_EXHAUSTED')
mem=next(int(l.split()[1])*1024 for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))
disk=os.statvfs(out);free=disk.f_bavail*disk.f_frsize
def ticks():return [int(n) for n in pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
a=ticks();time.sleep(.25);b=ticks();delta=[y-x for x,y in zip(a,b)];total=sum(delta)
if total<=0:reject('RESOURCE_STATE_UNKNOWN_BLOCKED')
busy=100*(1-(delta[3]+delta[4])/total)
budget={'scope':'LINUX_COSIGN_FIXED_FIXTURE','availableMemoryBytes':mem,'availableDiskBytes':free,'cpuBusyPercent':busy,'minimumMemoryBytes':1073741824,'minimumDiskBytes':1073741824,'maxCpuBusyPercent':75}
if mem<1073741824 or free<1073741824 or busy>75:reject('LINUX_RESOURCE_BUDGET_BLOCKED')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
resource.setrlimit(resource.RLIMIT_CPU,(20,25))
env={'PATH':'/usr/bin:/bin','HOME':str(out),'LANG':'C'}
argv=['/usr/bin/setpriv','--no-new-privs','/usr/bin/env','-i',*[k+'='+v for k,v in env.items()],'/usr/bin/node','--max-old-space-size=128',str(ROOT/'package/infra/security/testing/cosign-linux-web.mjs'),run,'controlled-finding' if finding else 'clean']
p=subprocess.Popen(argv,cwd=ROOT/'package',env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
def children():
 found=[]
 for item in pathlib.Path('/proc').iterdir():
  if not item.name.isdigit():continue
  try:
   if item.stat().st_uid!=uid:continue
   if (item/'exe').resolve()==ROOT/'cosign':found.append(int(item.name))
  except (OSError,RuntimeError):pass
 return found
def cancel(signum=None,frame=None):
 # The exclusive lock and dedicated UID bind these tool processes to this run.
 for pid in children():
  try:os.killpg(pid,signal.SIGTERM)
  except ProcessLookupError:pass
 try:os.killpg(p.pid,signal.SIGTERM)
 except ProcessLookupError:pass
signal.signal(signal.SIGTERM,cancel);signal.signal(signal.SIGHUP,cancel)
try:
 stdout,stderr=p.communicate(timeout=22)
except subprocess.TimeoutExpired:
 cancel()
 try:p.communicate(timeout=2)
 except subprocess.TimeoutExpired:
  for pid in children():
   try:os.killpg(pid,signal.SIGKILL)
   except ProcessLookupError:pass
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  p.communicate(timeout=2)
 reject('EXECUTION_TIMEOUT')
if children():cancel();reject('DESCENDANT_CLEANUP_FAILED')
if p.returncode!=0 or stderr or len(stdout)>524288:reject('EXECUTION_OR_OUTPUT_REJECTED')
try:packet=json.loads(stdout)
except (ValueError,UnicodeError):reject('RESULT_INVALID')
if packet.get('runId')!=run or packet.get('kind')!='RestrictedLinuxCosign':reject('RESULT_BINDING_REJECTED')
packet['budget']=budget
sys.stdout.write(json.dumps(packet)+'\n')
