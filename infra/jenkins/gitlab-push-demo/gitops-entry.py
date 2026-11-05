"""One fixed nonproduction ConfigMap transition, authorized by server-owned Gate proof."""
import os,sys,re,json,time,pathlib,hashlib,stat,subprocess,tempfile,fcntl,select
HOME=pathlib.Path('/var/lib/security-gitops-demo')
PROOFS=pathlib.Path('/var/lib/security-gitops-demo-proofs')
STATE=HOME/'state'
BRANCH='security-demo/gitops-20261105'
FILE='infra/devops-lab/gitops-demo/configmap.yaml'
def fail(code):print(json.dumps({'error':code}),flush=True);raise SystemExit(2)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def read(p,uid,mode,maxbytes=32768):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd) as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=mode or s.st_nlink!=1 or s.st_size>maxbytes:fail('FILE_BOUNDARY_REJECTED')
  return json.load(f)
if (os.getuid(),os.getgid())!=(24022,24022) or any(g!=24022 for g in os.getgroups()):fail('IDENTITY_REJECTED')
if not select.select([sys.stdin],[],[],2)[0] or sys.stdin.buffer.read(1):fail('INPUT_REJECTED')
cfg=read(HOME/'authorization.json',0,0o444)
command=os.environ.get('SSH_ORIGINAL_COMMAND','')
match=re.fullmatch(r'(update-v1|restore-v1) ([a-f0-9]{48}) ([a-f0-9]{64}) ([1-9][0-9]{0,7}) ([a-f0-9]{40})',command)
if not match:fail('FIXED_COMMAND_REQUIRED')
action,nonce,claimed,build,trigger=match.groups()
if int(build)!=cfg['build'] or trigger!=cfg['triggerCommit']:fail('BUILD_BINDING_REJECTED')
for p in ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml','/root/.ssh','/home/zhang/.kube/config']:
 if os.access(p,os.R_OK):fail('PRODUCTION_AUTHORITY_READABLE')
lock=open(STATE/'execution.lock','a')
try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:fail('EXECUTION_BUSY')
record=STATE/(nonce+'.json')
previous=read(record,24022,0o600) if record.exists() else None
if action=='update-v1' and previous:fail('RECEIPT_ALREADY_USED')
try:proof=read(PROOFS/(nonce+'.json'),24021,0o440)
except FileNotFoundError:fail('RECEIPT_NOT_FOUND')
raw={k:v for k,v in proof.items() if k!='receiptDigest'}
if proof['receiptId']!=nonce or digest(raw)!=proof['receiptDigest'] or claimed!=proof['receiptDigest']:fail('RECEIPT_DIGEST_MISMATCH')
if action=='update-v1':
 if int(time.time())>proof['expiresAt'] or proof['issuedAt']>int(time.time())+2:fail('RECEIPT_EXPIRED')
 if proof['scenarioId']!='clean' or proof['policyDecision']!='PASS' or proof['scannerExitCode']!=0 or proof['findingsCount']!=0 or proof['evaluationCount']!=1:fail('GATE_NOT_PASS')
 if proof['issuedAt']<cfg['notBefore']:fail('RECEIPT_OUTSIDE_RUN')
 if proof['toolSha256']!='db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d':fail('TOOL_IDENTITY_REJECTED')
else:
 if not previous or previous['state']!='UPDATED' or previous['runId']!=proof['runId'] or previous['resultDigest']!=proof['resultDigest']:fail('RESTORE_NOT_AUTHORIZED')
env={'PATH':'/usr/bin:/bin','HOME':str(HOME),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
 'GIT_CONFIG_NOSYSTEM':'1','GIT_TERMINAL_PROMPT':'0','GIT_NO_REPLACE_OBJECTS':'1',
 'GIT_ASKPASS':'/usr/local/libexec/security-gitops-demo-askpass','GIT_AUTHOR_NAME':'Restricted GitOps Demo',
 'GIT_AUTHOR_EMAIL':'security-gitops-demo@localhost','GIT_COMMITTER_NAME':'Restricted GitOps Demo','GIT_COMMITTER_EMAIL':'security-gitops-demo@localhost'}
with tempfile.TemporaryDirectory(prefix='git-',dir=STATE) as work:
 def git(args):
  r=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','-c','http.followRedirects=false',*args],cwd=work,env=env,capture_output=True,text=True,timeout=20)
  if r.returncode:fail('RESTRICTED_GIT_FAILED')
  if len(r.stdout)>65536:fail('GIT_OUTPUT_LIMIT')
  return r.stdout.strip()
 def save(v):
  tmp=STATE/(nonce+'.pending');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f:json.dump(v,f);f.flush();os.fsync(f.fileno())
  os.replace(tmp,record)
 remote=cfg['remote']
 if remote!='http://'+cfg['gitlabIp']+':'+str(cfg['gitlabPort'])+'/root/petclinic-platform.git':fail('REMOTE_REJECTED')
 git(['init','-q','--template=']);git(['fetch','--depth=3','--no-tags',remote,'refs/heads/'+BRANCH])
 head=git(['rev-parse','FETCH_HEAD'])
 expected=cfg['baselineCommit'] if action=='update-v1' else previous['updateCommit']
 if head!=expected:fail('CONCURRENT_BRANCH_CHANGE')
 git(['checkout','-q','--detach','FETCH_HEAD'])
 if git(['ls-tree','-r','--name-only','HEAD'])!=FILE:fail('TREE_SCOPE_REJECTED')
 file=pathlib.Path(work)/FILE
 if file.is_symlink() or file.resolve()!=file:fail('MANIFEST_PATH_REJECTED')
 original=json.loads(file.read_text());allowed=cfg['baselineManifest']
 target=json.loads(json.dumps(allowed));target['data']['demo-stage']='updated'
 if original!=(allowed if action=='update-v1' else target):fail('MANIFEST_SCOPE_REJECTED')
 if action=='update-v1':
  file.write_text(json.dumps(target,indent=2)+'\n');git(['add','--',FILE])
  git(['commit','-qm','demo: Gate PASS build '+build+' run '+proof['runId']+' [skip ci]'])
 else:git(['revert','--no-edit',previous['updateCommit']])
 after=json.loads(file.read_text())
 if after!=(target if action=='update-v1' else allowed):fail('FIELD_SCOPE_REJECTED')
 if git(['diff','--name-only',head,'HEAD'])!=FILE:fail('DIFF_SCOPE_REJECTED')
 sha=git(['rev-parse','HEAD'])
 journal={'state':'PUSH_PENDING','receiptId':nonce,'runId':proof['runId'],'resultDigest':proof['resultDigest'],
  'receiptDigest':claimed,'build':int(build),'triggerCommit':trigger,'beforeCommit':head,'operation':action,'afterCommit':sha,
  'updateCommit':sha if action=='update-v1' else previous['updateCommit'],'at':time.time()}
 save(journal) # Consume before side effect; failed/unknown push cannot be blindly retried.
 git(['push','--porcelain','-o','ci.skip',remote,'HEAD:refs/heads/'+BRANCH])
 if git(['ls-remote',remote,'refs/heads/'+BRANCH]).split()[0]!=sha:fail('PUSH_NOT_CONFIRMED')
 journal['state']='UPDATED' if action=='update-v1' else 'RESTORED';journal['value']='updated' if action=='update-v1' else 'baseline';save(journal)
 print(json.dumps(journal))
