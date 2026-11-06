"""Add finite Candidate level wiring only. No user/key/group/ACL or production Gate changes."""
import pathlib,subprocess,json,base64,hashlib,runpy
HERE=pathlib.Path(__file__).resolve().parent;REPO=HERE.parents[2]
api=runpy.run_path(str(REPO/'evidence/2026-11-05/security-manager-v2-loki/inspect-production.py'))
items=[]
for name,root,helper in [('gitleaks','/var/tmp/security-manager-gitleaks-v2-linux-20261105','gitleaks-linux-clean.mjs'),('semgrep','/var/tmp/security-manager-gitleaks-semgrep-web-20261106','semgrep-linux-web.mjs'),('cosign','/var/tmp/security-manager-gitleaks-cosign-web-20261106','cosign-linux-web.mjs')]:
 paths={'entry':'infra/security/testing/'+name+'-ssh-entry.py','helper':'infra/security/testing/'+helper}
 files={k:{'relative':p,'beforeSha256':hashlib.sha256(subprocess.check_output(['git','show','HEAD:'+p],cwd=REPO)).hexdigest(),'afterBase64':base64.b64encode((REPO/p).read_bytes()).decode()} for k,p in paths.items()}
 items.append({'name':name,'root':root,'files':files})
script=r'''
import pathlib,os,hashlib,base64,json,fcntl,ast,tempfile,subprocess,pwd
assert os.getuid()==0 and os.uname().nodename=='devops'
locks=[];plan=[];identities={}
for item in ITEMS:
 root=pathlib.Path(item['root']);lock=open(root/'outputs/execution.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(lock)
 account=pwd.getpwnam('security-'+item['name']);key=pathlib.Path(account.pw_dir)/'.ssh/authorized_keys'
 identities[item['name']]={'uid':account.pw_uid,'gid':account.pw_gid,'groups':subprocess.check_output(['id','-G',account.pw_name],text=True).strip(),'authorizedKeysSha256':hashlib.sha256(key.read_bytes()).hexdigest()}
 for kind,f in item['files'].items():
  p=root/'ssh-entry.py' if kind=='entry' else root/'package'/f['relative']
  s=p.lstat();assert p.resolve()==p and s.st_uid==0 and s.st_mode&0o777==0o444 and hashlib.sha256(p.read_bytes()).hexdigest()==f['beforeSha256'],str(p)
  data=base64.b64decode(f['afterBase64']);
  if kind=='entry':ast.parse(data)
  plan.append((p,data,item['name']+'/'+kind))
 manifest=root/'package-manifest.json';m=json.loads(manifest.read_text());helper=item['files']['helper'];assert m[helper['relative']]==helper['beforeSha256']
 m[helper['relative']]=hashlib.sha256(base64.b64decode(helper['afterBase64'])).hexdigest();plan.append((manifest,json.dumps(m).encode(),item['name']+'/manifest'))
jenkins=pathlib.Path('/usr/local/libexec/security-gitleaks-ci-proof.py');jenkinsHash=hashlib.sha256(jenkins.read_bytes()).hexdigest()
backup=pathlib.Path(tempfile.mkdtemp(prefix='security-view-config-backup-',dir='/var/tmp'));backup.chmod(0o700)
def write(p,data):
 temp=p.parent/(p.name+'.config-next');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
 with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(temp,p)
changed=[]
try:
 for p,data,relative in plan:
  b=backup/relative;b.parent.mkdir(parents=True,exist_ok=True);b.write_bytes(p.read_bytes());b.chmod(0o400)
  write(p,data);changed.append((p,b))
 for item in ITEMS:
  root=pathlib.Path(item['root']);m=json.loads((root/'package-manifest.json').read_text())
  for f in item['files'].values():
   if f['relative'].endswith('.mjs'):assert hashlib.sha256((root/'package'/f['relative']).read_bytes()).hexdigest()==m[f['relative']]
  account=pwd.getpwnam('security-'+item['name']);old=identities[item['name']]
  assert (account.pw_uid,account.pw_gid)==(old['uid'],old['gid']) and hashlib.sha256((pathlib.Path(account.pw_dir)/'.ssh/authorized_keys').read_bytes()).hexdigest()==old['authorizedKeysSha256']
 assert hashlib.sha256(jenkins.read_bytes()).hexdigest()==jenkinsHash
except Exception:
 for p,b in reversed(changed):write(p,b.read_bytes())
 raise
print(json.dumps({'backupDirectory':str(backup),'changedFiles':[str(p) for p,_ in changed],'identitiesUnchanged':identities,'jenkinsProofWrapperSha256':jenkinsHash,'existingJenkinsCommandDefault':'standard','newParameterAllowlist':['low','standard','strict'],'accountOrSshAuthorizationChanges':0,'productionGateChanges':0}))
'''
assert not (HERE/'execution-config-update.json').exists()
x=json.loads(api['remote']('sudo -n python3 -','ITEMS='+repr(items)+'\n'+script,timeout=40))
with (HERE/'execution-config-update.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
