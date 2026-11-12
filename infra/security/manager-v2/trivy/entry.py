"""Root-owned fixed SSH entry. No caller-provided image, path or scanner arguments."""
import os,sys,json,pathlib,hashlib,subprocess,time,re,fcntl,signal,resource,datetime
ROOT=pathlib.Path('/var/lib/security-trivy')
STAGES=[];CHILD={'p':None}
def _term(signum,frame):
 p=CHILD['p']
 if p is not None:
  try:os.killpg(p.pid,signal.SIGKILL)
  except Exception:pass
 raise RuntimeError('RUNNER_TERMINATED')
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def iso():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def main():
 command=os.environ.get('SSH_ORIGINAL_COMMAND','');m=re.fullmatch(r'scan-v1 ([a-zA-Z0-9_.-]+) (web-[a-f0-9-]{36})',command)
 if not m:raise RuntimeError('COMMAND_REJECTED')
 project,run=m.groups();cfg=json.loads((ROOT/'projects.json').read_text());p=cfg['projects'].get(project)
 if not p:raise RuntimeError('PROJECT_NOT_AUTHORIZED')
 if os.getuid()!=cfg['uid']or os.getgid()!=cfg['gid']or os.getgroups()not in [[],[cfg['gid']]]:raise RuntimeError('IDENTITY_REJECTED')
 if not re.search(r'NoNewPrivs:\s+1',pathlib.Path('/proc/self/status').read_text()):raise RuntimeError('IDENTITY_REJECTED')
 for forbidden in ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml','/var/run/secrets/kubernetes.io/serviceaccount/token']:
  if os.access(forbidden,os.R_OK):raise RuntimeError('PRODUCTION_AUTHORITY_READABLE')
 if sha(ROOT/'bin/trivy')!=cfg['toolSha256']:raise RuntimeError('TOOL_DIGEST_REJECTED')
 mem=next(int(s.split()[1])*1024 for s in pathlib.Path('/proc/meminfo').read_text().splitlines()if s.startswith('MemAvailable:'))
 import shutil
 if mem<2*1024**3 or shutil.disk_usage(ROOT).free<8*1024**3 or os.getloadavg()[0]>os.cpu_count()*.75:raise RuntimeError('RESOURCE_BUDGET_BLOCKED')
 db=[];now=time.time()
 for name,version in [('db',2),('java-db',1)]:
  path=ROOT/'db-cache'/name/'metadata.json';v=json.loads(path.read_text());updated=datetime.datetime.fromisoformat(v['UpdatedAt'].replace('Z','+00:00')).timestamp()
  if v['Version']!=version or not 0<=now-updated<72*3600:raise RuntimeError('DB_FRESHNESS_BLOCKED')
  if v.get('NextUpdate')and datetime.datetime.fromisoformat(v['NextUpdate'].replace('Z','+00:00')).timestamp()<=now:raise RuntimeError('DB_EXPIRED_BLOCKED')
  db.append({'name':name,'metadata':v,'metadataSha256':sha(path)})
 creds=json.loads((ROOT/'credentials.json').read_text())
 if creds.get('expiresAt',0)<=now:raise RuntimeError('CREDENTIAL_EXPIRED_BLOCKED')
 lock=open(ROOT/'data/execution.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 marker=ROOT/'data/formal-scan-attempt.json'
 try:fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 except FileExistsError:raise RuntimeError('FORMAL_SCAN_ALREADY_CONSUMED')
 os.write(fd,json.dumps({'runId':run,'projectId':project,'startedAt':iso()}).encode());os.close(fd)
 work=ROOT/'data'/run;work.mkdir(mode=0o700);report=work/'native.json';started=iso()
 stages=STAGES
 def stage(name,**kw):
  stages.append({'runId':run,'stage':name,'at':iso(),**kw});tmp=work/'stages.tmp';tmp.write_text(json.dumps(stages));os.replace(tmp,work/'stages.json')
 stage('SOURCE_READY');env={'PATH':'/usr/bin:/bin','HOME':str(ROOT/'data'),'TMPDIR':str(work),'LANG':'C','GOMAXPROCS':'1','GOMEMLIMIT':'1536MiB','TRIVY_USERNAME':creds['username'],'TRIVY_PASSWORD':creds['password']}
 image=p['registry']+'/'+p['repository']+'@'+p['platformDigest']
 args=[str(ROOT/'bin/trivy'),'--config',str(ROOT/'trivy.yaml'),'image','--insecure','--platform','linux/arm64','--image-src','remote','--scanners','vuln','--skip-db-update','--skip-java-db-update','--skip-check-update','--offline-scan','--parallel','1','--timeout','180s','--cache-dir',str(ROOT/'db-cache'),'--format','json','--output',str(report),'--exit-code','0',image]
 log=open(work/'execution.log','xb');stage('SCANNER_START_ATTEMPT')
 signal.signal(signal.SIGTERM,_term);signal.signal(signal.SIGHUP,_term)
 child=subprocess.Popen(args,cwd=work,env=env,stdout=log,stderr=log,start_new_session=True);CHILD['p']=child;stage('SCANNER_STARTED',pid=child.pid)
 try:code=child.wait(timeout=185)
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGKILL);child.wait();stage('RUN_FAILED',errorCategory='RUNNER_TIMEOUT');raise RuntimeError('RUNNER_TIMEOUT')
 finally:log.close()
 stage('SCANNER_EXITED',exitCode=code)
 if code!=0:stage('RUN_FAILED',errorCategory='SCANNER_ERROR');raise RuntimeError('SCANNER_ERROR')
 if not report.is_file()or report.stat().st_size>16*1024**2:raise RuntimeError('REPORT_REJECTED')
 raw=json.loads(report.read_text());results=[];count=0
 for r in raw.get('Results',[]):
  findings=[]
  for v in r.get('Vulnerabilities',[]):
   findings.append({k:v[k]for k in ['VulnerabilityID','PkgName','InstalledVersion','FixedVersion','Severity','PrimaryURL']if k in v});count+=1
  results.append({k:r[k]for k in ['Target','Class','Type']if k in r}|{'Vulnerabilities':findings})
 if count>10000:raise RuntimeError('OUTPUT_BUDGET_BLOCKED')
 safe={'SchemaVersion':raw.get('SchemaVersion'),'ArtifactName':image,'ArtifactType':raw.get('ArtifactType'),'Results':results};text=json.dumps(safe,separators=(',',':'),ensure_ascii=False);assert len(text.encode())<2*1024**2
 (work/'sanitized.json').write_text(text);stage('RESULT_VALIDATED');stage('RUN_COMPLETED')
 print(json.dumps({'kind':'RestrictedLinuxTrivy','projectId':project,'runId':run,'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'noNewPrivs':True,'indexDigest':p['indexDigest'],'platformDigest':p['platformDigest'],'platform':'linux/arm64','toolVersion':cfg['toolVersion'],'toolSha256':cfg['toolSha256'],'exitCode':code,'startedAt':started,'completedAt':iso(),'db':db,'findingCount':count,'nativeReportSha256':sha(report),'rawReportSha256':hashlib.sha256(text.encode()).hexdigest(),'rawReport':safe,'stages':stages,'cleanup':'SCANNER_EXITED','robotId':creds['robotId']}))
try:main()
except Exception as e:
 code=str(e)if re.fullmatch('[A-Z_]{3,80}',str(e))else 'EXECUTION_REJECTED'
 try:print(json.dumps({'error':code,'stages':STAGES}))
 except Exception:pass
 sys.exit(1)
