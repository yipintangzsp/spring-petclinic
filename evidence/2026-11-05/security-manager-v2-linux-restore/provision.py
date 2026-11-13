"""Approved fixed devops host only; no production service or account edits."""
import base64,hashlib,io,json,pathlib,re,subprocess,sys,tarfile,uuid,os
HERE=pathlib.Path(__file__).resolve().parent
REPO=HERE.parents[2]
KEY=pathlib.Path('/Users/zhangsir/.ssh/security-manager-v2-gitleaks')
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','ConnectionAttempts=1',
 '-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
DOMAIN='/var/tmp/security-manager-gitleaks-v2-linux-20261105'
HOME='/var/lib/security-gitleaks'
IMAGE='127.0.0.1:30050/platform-security/gitleaks@sha256:6b2d52241f9d176fc59e6e3b026ea52c98f390070587d9475d6ee2bc64941815'
SHA='db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d'
def save(name,obj):
 with (HERE/name).open('x') as f:json.dump(obj,f,indent=2);f.write('\n')
def remote(script,timeout=35):
 p=subprocess.run(SSH+['sudo -n /usr/bin/python3 -I -'],input=script,text=True,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError(p.stderr[-6000:] or p.stdout[-1500:])
 return json.loads(p.stdout)
prefix=f'ROOT={DOMAIN!r}\nHOME={HOME!r}\nIMAGE={IMAGE!r}\nSHA={SHA!r}\n'
preflight=r'''
import os,pathlib,subprocess,shutil,json
def check():
 assert os.getuid()==0 and os.uname().machine=='aarch64' and os.uname().nodename=='devops'
 for database,entry in [('passwd','security-gitleaks'),('passwd','24021'),('group','security-gitleaks'),('group','24021')]:
  assert subprocess.run(['getent',database,entry],stdout=subprocess.DEVNULL,timeout=4).returncode==2,(database,entry)
 for d in [ROOT,HOME]:assert not os.path.lexists(d),d
 assert pathlib.Path('/var/tmp').resolve()==pathlib.Path('/var/tmp')
 assert pathlib.Path('/var/lib').resolve()==pathlib.Path('/var/lib')
 for p in ['/usr/bin/node','/usr/bin/setpriv','/usr/bin/git','/usr/sbin/useradd','/usr/sbin/groupadd']:assert os.access(p,os.X_OK),p
 mem=next(int(l.split()[1])*1024 for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))
 disk=shutil.disk_usage('/var/tmp').free
 assert mem>1024**3 and disk>1024**3
 assert os.stat('/run/docker.sock').st_mode&0o777==0o660
 cached=subprocess.check_output(['k3s','ctr','-n','k8s.io','images','ls','-q'],text=True,timeout=12)
 assert IMAGE in cached.splitlines()
 return {'host':os.uname().nodename,'architecture':os.uname().machine,'uidAvailable':24021,'gidAvailable':24021,'newDirectoriesAbsent':[ROOT,HOME],'memoryAvailable':mem,'diskFree':disk,'imageCached':True}
'''
def package():
 files=set()
 def add(p):
  p=p.resolve()
  if p in files:return
  assert p.is_relative_to(REPO) and p.is_file()
  files.add(p)
  if p.suffix=='.mjs':
   for rel in re.findall(r"""(?:from\s*|import\s*\(|new URL\s*\()\s*['"](\.[^'"]+)['"]""",p.read_text()):
    q=p.parent/rel
    if q.is_file():add(q)
 add(REPO/'infra/security/testing/gitleaks-linux-clean.mjs')
 for folder in ['infra/security/policy/versions','infra/security/manager-v2/policies','infra/security/manager-v2/fixtures']:
  for p in (REPO/folder).glob('*.json'):add(p)
 add(REPO/'infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs')
 for name in json.loads((REPO/'infra/security/policy/versions/gitleaks-parent-baseline-v1.json').read_text())['sourceHashes']:add(REPO/name)
 manifest={}
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w:gz') as tar:
  for p in sorted(files):
   b=p.read_bytes();name=str(p.relative_to(REPO));assert len(b)<1024**2
   manifest[name]=hashlib.sha256(b).hexdigest()
   info=tarfile.TarInfo(name);info.size=len(b);info.mode=0o444;tar.addfile(info,io.BytesIO(b))
 return stream.getvalue(),manifest
install=r'''
import hashlib,base64,tarfile,io,struct,stat
before=check();os.umask(0o077)
root=pathlib.Path(ROOT);root.mkdir(mode=0o700)
archive=root/'cached.oci'
try:
 subprocess.run(['k3s','ctr','-n','k8s.io','images','export','--platform','linux/arm64',str(archive),IMAGE],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=55)
 assert archive.stat().st_size<128*1024**2
 with tarfile.open(archive) as tar:
  def blob(d):
   assert d.startswith('sha256:') and len(d)==71
   b=tar.extractfile('blobs/'+d.replace(':','/')).read();assert 'sha256:'+hashlib.sha256(b).hexdigest()==d
   return b
  manifestDigest=IMAGE.split('@')[1];descriptor=json.loads(blob(manifestDigest))
  if 'manifests' in descriptor:
   manifestDigest=next(x['digest'] for x in descriptor['manifests'] if x.get('platform',{}).get('os')=='linux' and x.get('platform',{}).get('architecture')=='arm64');descriptor=json.loads(blob(manifestDigest))
  config=json.loads(blob(descriptor['config']['digest']));assert (config['os'],config['architecture'])==('linux','arm64')
  binary=None;layerDigest=None
  for layer in descriptor['layers']:
   with tarfile.open(fileobj=io.BytesIO(blob(layer['digest'])),mode='r:*') as lt:
    for member in lt:
     if member.name.lstrip('./') in ['usr/bin/gitleaks','usr/local/bin/gitleaks','gitleaks']:
      assert member.isfile() and member.size<100*1024**2
      binary=lt.extractfile(member).read();layerDigest=layer['digest']
  assert binary and binary[:4]==b'\x7fELF' and struct.unpack('<H',binary[18:20])[0]==183
  assert hashlib.sha256(binary).hexdigest()==SHA
 (root/'gitleaks').write_bytes(binary);(root/'gitleaks').chmod(0o555)
finally:
 if archive.exists():archive.unlink()
payload=base64.b64decode(PAYLOAD,validate=True);assert hashlib.sha256(payload).hexdigest()==PAYLOAD_SHA
package=root/'package';package.mkdir(mode=0o700)
with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as tar:
 members=tar.getmembers();assert len(members)<300 and sum(m.size for m in members)<4*1024**2
 assert len({m.name for m in members})==len(members) and {m.name for m in members}==set(MANIFEST)
 for m in members:
  q=pathlib.PurePosixPath(m.name);assert m.isfile() and not q.is_absolute() and '..' not in q.parts
  data=tar.extractfile(m).read();assert hashlib.sha256(data).hexdigest()==MANIFEST[m.name]
  dest=package/q;dest.parent.mkdir(parents=True,exist_ok=True)
  with dest.open('xb') as f:f.write(data)
  dest.chmod(0o444)
for d,ds,fs in os.walk(package,topdown=False):pathlib.Path(d).chmod(0o555)
fixture=b'# Disposable cross-project validation fixture\nprint("public clean fixture")\n'
repo=root/'fixture-build';repo.mkdir(mode=0o700)
env={'PATH':'/usr/bin:/bin','HOME':str(repo),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','LANG':'C'}
def git(*args):
 return subprocess.check_output(['/usr/bin/git','-c','core.hooksPath=/dev/null',*args],cwd=repo,env=env,stderr=subprocess.PIPE,timeout=7)
git('init','--quiet');(repo/'app.py').write_bytes(fixture);git('add','app.py')
git('-c','user.name=Validation Fixture','-c','user.email=validation@example.invalid','commit','--quiet','-m','Disposable non-production source')
rev=git('rev-parse','HEAD').decode().strip();assert git('show',rev+':app.py')==fixture
src=root/'source-python';src.mkdir(mode=0o700);(src/'app.py').write_bytes(fixture);(src/'app.py').chmod(0o444);src.chmod(0o555)
shutil.rmtree(repo)
out=root/'outputs';out.mkdir(mode=0o700)
binding=[{'path':'app.py','bytes':len(fixture),'sha256':hashlib.sha256(fixture).hexdigest()}];st=src.stat()
tool={'path':str(root/'gitleaks'),'version':'8.30.1','sha256':SHA,'image':IMAGE,'bytes':len(binary)}
approval={'schemaVersion':1,'scope':'SYNTHETIC_NON_RELEASE_DIR_SCAN','workspace':ROOT,'executionUid':24021,'outputRoot':str(out),'tool':tool,
 'sources':[{'projectId':'python-fixture','profile':'python-api','sourceDir':str(src),'sourceRevision':rev,'inode':st.st_ino,'device':st.st_dev,'fileManifestDigest':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()}]}
for name,data in [('approval.json',json.dumps(approval).encode()),('package-manifest.json',json.dumps(MANIFEST).encode()),('ssh-entry.py',base64.b64decode(ENTRY,validate=True))]:
 with (root/name).open('xb') as f:f.write(data)
 (root/name).chmod(0o444)
subprocess.run(['/usr/sbin/groupadd','--gid','24021','security-gitleaks'],check=True,timeout=8)
try:
 subprocess.run(['/usr/sbin/useradd','--system','--no-create-home','--uid','24021','--gid','security-gitleaks','--home-dir',HOME,'--shell','/bin/sh','security-gitleaks'],check=True,timeout=8)
except Exception:
 subprocess.run(['/usr/sbin/groupdel','security-gitleaks'],check=True,timeout=8);raise
home=pathlib.Path(HOME);home.mkdir(mode=0o755);home.chmod(0o755)
ssh=home/'.ssh';ssh.mkdir(mode=0o700)
os.chown(out,24021,24021)
assert subprocess.check_output(['id','-G','security-gitleaks'],text=True,timeout=5).strip()=='24021'
passwordStatus=subprocess.check_output(['/usr/bin/passwd','-S','security-gitleaks'],text=True,timeout=5).split()[1]
assert passwordStatus=='L'
sudo=subprocess.run(['/usr/bin/sudo','-n','-l','-U','security-gitleaks'],capture_output=True,text=True,timeout=7)
assert (sudo.stdout+sudo.stderr).strip()=='User security-gitleaks is not allowed to run sudo on devops.'
root.chmod(0o755)
print(json.dumps({'preflight':before,'account':{'name':'security-gitleaks','uid':24021,'gid':24021,'groups':[24021],'passwordLocked':True,'sudoDenied':True},'tool':tool,
 'verifiedOciManifest':manifestDigest,'verifiedOciLayer':layerDigest,'fixture':approval['sources'][0],'packageFileCount':len(MANIFEST),'packageSha256':PAYLOAD_SHA,
 'sshKeyInstalled':False,'directories':{'domainMode':'0755 root:root','packageMode':'0555 root:root','outputMode':'0700 24021:24021','homeMode':'0755 root:root','sshMode':'0700 root:root'}}))
'''
localrun=r'''
import os,subprocess,json,pathlib
run=subprocess.run(['/usr/bin/setpriv','--reuid=24021','--regid=24021','--clear-groups','--no-new-privs','--bounding-set=-all',
 '/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C','HOME='+HOME,'SSH_ORIGINAL_COMMAND=clean-v1 '+RUN,
 '/usr/bin/python3','-I',ROOT+'/ssh-entry.py'],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=32)
if run.returncode:
 # Diagnostic error codes and bounded operator-only stderr; no raw reports or credentials.
 raise RuntimeError('restricted command failed: '+run.stdout[:500]+' '+run.stderr[-2500:])
packet=json.loads(run.stdout);assert packet['runId']==RUN
print(json.dumps({'origin':'LINUX_LOCAL_OPERATOR_NOT_WEB','packet':packet}))
'''
def preflight_only():save('approved-preflight.json',remote(prefix+preflight+'\nprint(json.dumps(check()))'))
def prepare():
 blob,manifest=package()
 entry=(REPO/'infra/security/testing/gitleaks-ssh-entry.py').read_bytes()
 payload=f'PAYLOAD={base64.b64encode(blob).decode()!r}\nPAYLOAD_SHA={hashlib.sha256(blob).hexdigest()!r}\nMANIFEST={manifest!r}\nENTRY={base64.b64encode(entry).decode()!r}\n'
 save('installed.json',remote(prefix+payload+preflight+install,timeout=105))
 print('Dedicated account and fixed release prepared; no SSH key authorized')
def clean():
 run='web-'+str(uuid.uuid4())
 x=remote(prefix+f'RUN={run!r}\n'+localrun,timeout=40)
 save('linux-local-clean.json',x)
 p=x['packet'];r=p['result'];f=r['runtimeFacts']
 print(json.dumps({'runId':p['runId'],'identity':f['identity'],'tool':f['tool'],'exit':f['command']['exitStatus'],'policy':r['policyDecision'],'evaluations':r['evaluationCount'],'digest':r['resultDigest'],'rawDigest':r['rawReportDigest']}))
def finish_prepared():
 _,manifest=package()
 entry=(REPO/'infra/security/testing/gitleaks-ssh-entry.py').read_bytes()
 script=r'''
import pathlib,os,stat,json,subprocess,hashlib
assert os.getuid()==0 and os.uname().nodename=='devops'
root=pathlib.Path(ROOT);home=pathlib.Path(HOME)
def check(p,uid,gid,mode,kind):
 st=p.lstat()
 assert p.resolve()==p and st.st_uid==uid and st.st_gid==gid and st.st_mode&0o777==mode and kind(st.st_mode),str(p)
check(root,0,0,0o700,stat.S_ISDIR);check(home,0,0,0o755,stat.S_ISDIR)
check(home/'.ssh',0,0,0o700,stat.S_ISDIR);assert not list((home/'.ssh').iterdir())
assert not (root/'cached.oci').exists()
check(root/'outputs',24021,24021,0o700,stat.S_ISDIR);assert not list((root/'outputs').iterdir())
check(root/'package',0,0,0o555,stat.S_ISDIR)
for name in ['approval.json','package-manifest.json','ssh-entry.py']:check(root/name,0,0,0o444,stat.S_ISREG)
assert hashlib.sha256((root/'ssh-entry.py').read_bytes()).hexdigest()==ENTRY_SHA
assert json.loads((root/'package-manifest.json').read_text())==MANIFEST
for name,digest in MANIFEST.items():
 p=root/'package'/name;check(p,0,0,0o444,stat.S_ISREG);assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
check(root/'gitleaks',0,0,0o555,stat.S_ISREG)
assert hashlib.sha256((root/'gitleaks').read_bytes()).hexdigest()==SHA
check(root/'source-python',0,0,0o555,stat.S_ISDIR)
check(root/'source-python/app.py',0,0,0o444,stat.S_ISREG)
assert (root/'source-python/app.py').read_bytes()==b'# Disposable cross-project validation fixture\nprint("public clean fixture")\n'
assert subprocess.check_output(['id','-u','security-gitleaks'],text=True).strip()=='24021'
assert subprocess.check_output(['id','-G','security-gitleaks'],text=True).strip()=='24021'
assert subprocess.check_output(['/usr/bin/passwd','-S','security-gitleaks'],text=True).split()[1]=='L'
s=subprocess.run(['/usr/bin/sudo','-n','-l','-U','security-gitleaks'],capture_output=True,text=True,timeout=7)
assert (s.stdout+s.stderr).strip()=='User security-gitleaks is not allowed to run sudo on devops.'
root.chmod(0o755)
approval=json.loads((root/'approval.json').read_text())
print(json.dumps({'account':{'name':'security-gitleaks','uid':24021,'gid':24021,'groups':[24021],'passwordLocked':True,'sudoDenied':True},
 'tool':approval['tool'],'fixture':approval['sources'][0],'packageFileCount':len(MANIFEST),
 'resumedAfterSudoListExitMismatch':True,'sudoListExit':s.returncode,'sshKeyInstalled':False,
 'directories':{'domainMode':'0755 root:root','packageMode':'0555 root:root','outputMode':'0700 24021:24021','homeMode':'0755 root:root','sshMode':'0700 root:root'}}))
'''
 save('installed.json',remote(prefix+f'MANIFEST={manifest!r}\nENTRY_SHA={hashlib.sha256(entry).hexdigest()!r}\n'+script))
def authorize():
 assert (HERE/'linux-local-clean.json').is_file()
 assert not KEY.is_symlink() and KEY.is_file() and KEY.stat().st_uid==os.getuid() and not KEY.stat().st_mode&0o077
 pub=subprocess.check_output(['/usr/bin/ssh-keygen','-y','-f',str(KEY)],text=True,timeout=6).strip().split()
 assert pub[0]=='ssh-ed25519' and len(pub)>=2 and re.fullmatch(r'[A-Za-z0-9+/=]+',pub[1])
 line='restrict,command="/usr/bin/python3 -I '+DOMAIN+'/ssh-entry.py" '+ ' '.join(pub[:2])+' security-manager-v2-gitleaks-clean-only\n'
 script=r'''
import os,pathlib,json
p=pathlib.Path(HOME+'/.ssh/authorized_keys')
assert p.parent.resolve()==p.parent and p.parent.stat().st_uid==0 and p.parent.stat().st_mode&0o777==0o700
# sshd reads authorized_keys as the target UID. Keep the file root-writable
# only, with read/traverse granted to this dedicated group and nobody else.
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:
 f.write(LINE);f.flush();os.fchown(f.fileno(),0,24021);os.fchmod(f.fileno(),0o640);os.fsync(f.fileno())
os.chown(p.parent,0,24021);p.parent.chmod(0o750)
print(json.dumps({'account':'security-gitleaks','keyPath':str(p),'mode':'0640 root:24021','sshDirectory':'0750 root:24021','forcedCommand':'clean-only','sshdChanged':False}))
'''
 save('ssh-authorized.json',remote(prefix+f'LINE={line!r}\n'+script))
 print('Dedicated forced-command public key authorized')
if __name__=='__main__':
 {'preflight':preflight_only,'prepare':prepare,'finish-prepared':finish_prepared,'clean':clean,'authorize':authorize}[sys.argv[1]]()
