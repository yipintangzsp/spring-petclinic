"""Fixed authorized source phase; Git objects verified before existing Manager runner."""
import pathlib,os,sys,json,subprocess,hashlib,io,tarfile,gzip,shutil,tempfile,re,time,fcntl,signal,resource,importlib.util
ROOT=pathlib.Path('/var/tmp/security-manager-gitleaks-recovery-20261107')
def fail(code):
 if 'run'in globals()and(ROOT/'outputs').is_dir():
  f=ROOT/'outputs'/(run+'-stages.jsonl')
  with f.open('a')as out:out.write(json.dumps({'runId':run,'stage':'RUN_FAILED','time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'exitCode':None,'errorCategory':code,'summary':'Source admission or execution rejected'})+'\n');out.flush();os.fsync(out.fileno())
 print(json.dumps({'error':code}),flush=True);sys.exit(2)
cmd=os.environ.get('SSH_ORIGINAL_COMMAND','').split()
if len(cmd)!=3 or cmd[0]!='commit-v1' or not re.fullmatch('web-[a-f0-9-]{36}',cmd[1])or cmd[2]not in ['low','standard','strict']:fail('SOURCE_COMMAND_REJECTED')
if os.getuid()!=24021 or os.getgid()!=24021 or os.getgroups()!=[24021]:fail('SOURCE_IDENTITY_REJECTED')
run=cmd[1];level=cmd[2]
# Adopt only our own orphan descendants so disconnect/timeout cleanup stays bounded.
import ctypes
if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:fail('SOURCE_PROCESS_BOUNDARY_UNAVAILABLE')
def descendants(pid=os.getpid()):
 result=[]
 try:children=list(map(int,pathlib.Path('/proc/'+str(pid)+'/task/'+str(pid)+'/children').read_text().split()))
 except FileNotFoundError:return result
 for child in children:result.extend(descendants(child));result.append(child)
 return result
def stop_descendants():
 for sig in [signal.SIGTERM,signal.SIGKILL]:
  for pid in descendants():
   try:os.kill(pid,sig)
   except ProcessLookupError:pass
  time.sleep(.1)
  while True:
   try:
    if os.waitpid(-1,os.WNOHANG)[0]==0:break
   except ChildProcessError:break
 if descendants():raise RuntimeError('SOURCE_DESCENDANT_CLEANUP_FAILED')
def interrupted(signum,frame):raise RuntimeError('SOURCE_CANCELLED')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGHUP,interrupted)

for p in ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml']:
 if os.access(p,os.R_OK):fail('PRODUCTION_AUTHORITY_READABLE')
for p in [ROOT,ROOT/'approval.json',ROOT/'package',ROOT/'askpass.py']:
 s=p.lstat()
 if p.resolve()!=p or s.st_uid!=0 or s.st_mode&0o022:fail('SOURCE_RELEASE_UNTRUSTED')
cfg=json.loads((ROOT/'approval.json').read_text())
if cfg['expiresAt']<=time.time()*1000:fail('SOURCE_AUTHORIZATION_EXPIRED')
if not re.fullmatch('[a-f0-9]{40}',cfg['commitSha']):fail('SOURCE_COMMIT_REJECTED')
if cfg.get('budgetScope')!={'projectId':cfg['projectId'],'commitSha':cfg['commitSha']}or cfg['limits']['fileBytes']!=4194304:fail('SOURCE_LIMIT_SCOPE_REJECTED')
for name,h in json.loads((ROOT/'package-manifest.json').read_text()).items():
 p=ROOT/'package'/name;s=p.lstat()
 if p.resolve()!=p or s.st_uid!=0 or s.st_mode&0o022 or hashlib.sha256(p.read_bytes()).hexdigest()!=h:fail('SOURCE_RELEASE_UNTRUSTED')
lock=open(ROOT/'outputs/execution.lock','a')
try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:fail('EXECUTION_BUSY')
mem=int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')))*1024
def ticks():return list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
a=ticks();time.sleep(.25);b=ticks();d=[y-x for x,y in zip(a,b)];busy=100*(1-(d[3]+d[4])/sum(d))if sum(d)>0 else 100
if mem<1073741824 or shutil.disk_usage(ROOT).free<1073741824 or busy>75:fail('LINUX_RESOURCE_BUDGET_BLOCKED')
# One source invocation is exclusive even if preparation later fails.
marker=ROOT/'outputs/source-attempt.json'
try:
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
 with os.fdopen(fd,'w')as f:json.dump({'runId':run,'commitSha':cfg['commitSha'],'at':time.time(),'scannerStarted':False},f)
except FileExistsError:fail('SOURCE_ONE_RUN_BUDGET_USED')
work=ROOT/'outputs'/('source-'+run);work.mkdir(mode=0o700);gitdir=work/'git';source=work/'source';stage='SOURCE_FETCH';child=None
try:
 env={'PATH':'/usr/bin:/bin','HOME':str(work),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':str(ROOT/'askpass.py'),'GIT_OPTIONAL_LOCKS':'0','GIT_LFS_SKIP_SMUDGE':'1'}
 def git(args,limit=40*1024*1024,input_bytes=None):
  p=subprocess.Popen(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false',*args],cwd=work,env=env,stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  try:out,err=p.communicate(input=input_bytes,timeout=40)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);p.communicate(timeout=3);raise RuntimeError('SOURCE_FETCH_TIMEOUT')
  if p.returncode or len(out)>limit:raise RuntimeError('SOURCE_FETCH_OR_OBJECT_ERROR')
  return out
 git(['init','--bare','-q',str(gitdir)]);base=['--git-dir='+str(gitdir)]
 git(base+['fetch','--depth=1','--no-tags',cfg['gitRemote'],'refs/heads/'+cfg['branch']],1024)
 sha=git(base+['rev-parse','FETCH_HEAD'],100).decode().strip()
 if sha!=cfg['commitSha']:raise RuntimeError('SOURCE_BRANCH_COMMIT_MISMATCH')
 commit=git(base+['cat-file','commit',sha],65536)
 if hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()!=sha:raise RuntimeError('SOURCE_COMMIT_OBJECT_MISMATCH')
 tree=commit.splitlines()[0].decode().removeprefix('tree ')
 if tree!=cfg['rootTreeOid']:raise RuntimeError('SOURCE_ROOT_TREE_MISMATCH')
 treebytes=git(base+['ls-tree','-rz','--full-tree',sha],1024*1024);entries={}
 for item in treebytes.split(b'\0'):
  if not item:continue
  meta,name=item.split(b'\t',1);mode,kind,oid=meta.decode().split();rel=name.decode('utf-8')
  if kind!='blob' or mode not in ['100644','100755']:raise RuntimeError('SOURCE_UNSUPPORTED_GIT_ENTRY')
  entries[rel]={'mode':mode,'oid':oid}
 if len(entries)>cfg['limits']['files']:raise RuntimeError('SOURCE_FILE_BUDGET')
 spec=importlib.util.spec_from_file_location('snapshot',ROOT/'package/infra/security/manager-v2/ci/source-snapshot.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 batch=git(base+['cat-file','--batch'],cfg['limits']['expandedBytes']+cfg['limits']['files']*128,(''.join(entries[p]['oid']+'\n'for p in sorted(entries))).encode());archive=mod.canonical_blob_archive(entries,batch,cfg['limits']);del batch
 proof=mod.materialize_verified_archive(archive,entries,source,cfg['limits']);proof.update({'budgetScope':cfg['budgetScope'],'gitEntries':entries,'commitSha':sha,'rootTreeOid':tree,'projectId':cfg['projectId'],'repository':cfg['sourceRepository'],'branch':cfg['branch']});(work/'source-proof.json').write_text(json.dumps(proof));shutil.rmtree(gitdir);del archive
 (ROOT/'outputs'/(run+'-stages.jsonl')).write_text(json.dumps({'runId':run,'stage':'SOURCE_READY','time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'exitCode':None,'errorCategory':None,'summary':None})+'\n')
 stage='SCANNER'
 env={'PATH':'/usr/bin:/bin','HOME':str(work),'LANG':'C'}
 child=subprocess.Popen(['/usr/bin/setpriv','--no-new-privs','/usr/bin/env','-i',*[k+'='+v for k,v in env.items()],'/usr/bin/node','--max-old-space-size=128',str(ROOT/'package/infra/security/manager-v2/ci/commit-run.mjs'),run,level],cwd=ROOT/'package',env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:out,err=child.communicate(timeout=25)
 except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGTERM);child.communicate(timeout=3);raise RuntimeError('RUNNER_TIMEOUT')
 if child.returncode or len(out)>2*1024*1024:
  (ROOT/'outputs'/(run+'-process.json')).write_text(json.dumps({'exitCode':child.returncode,'stderrSha256':hashlib.sha256(err).hexdigest(),'stderrBytes':len(err),'stdoutBytes':len(out)}));raise RuntimeError('RUNNER_OR_COLLECTION_ERROR')
 packet=json.loads(out)
 if packet['runId']!=run:raise RuntimeError('SOURCE_RESULT_BINDING')
 if work.exists():raise RuntimeError('SOURCE_CLEANUP_FAILED')
 stop_descendants()
 print(json.dumps(packet),flush=True)
except BaseException as e:
 code=str(e)if isinstance(e,(RuntimeError,ValueError))and re.fullmatch('[A-Z_]+',str(e))else('SOURCE_ERROR'if stage!='SCANNER'else'RUNNER_OR_COLLECTION_ERROR')
 stop_descendants()
 with(ROOT/'outputs'/(run+'-stages.jsonl')).open('a')as f:f.write(json.dumps({'runId':run,'stage':'RUN_FAILED','time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'exitCode':child.returncode if child else None,'errorCategory':code,'summary':'Source or Manager process failed'})+'\n');f.flush();os.fsync(f.fileno())
 if work.exists():shutil.rmtree(work)
 (ROOT/'outputs'/(run+'-error.json')).write_text(json.dumps({'runId':run,'stage':stage,'error':code,'sourceCleanup':not work.exists(),'scannerStarted':stage=='SCANNER'}));fail(code)
finally:
 stop_descendants()
 if work.exists():shutil.rmtree(work)
