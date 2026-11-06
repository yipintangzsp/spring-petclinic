"""One-shot authorized dedicated Semgrep identity; existing production identities untouched."""
import runpy,pathlib,json,hashlib,re,io,tarfile,base64,subprocess,os
HERE=pathlib.Path(__file__).resolve().parent;REPO=HERE.parents[2]
api=runpy.run_path(str(REPO/'evidence/2026-11-05/security-manager-v2-loki/inspect-production.py'))
ROOT='/var/tmp/security-manager-gitleaks-semgrep-web-20261106';HOME='/var/lib/security-semgrep'
files=set()
def add(p):
 p=p.resolve()
 if p in files:return
 assert p.is_relative_to(REPO) and p.is_file();files.add(p)
 if p.suffix=='.mjs':
  for rel in re.findall(r'''(?:from\s*|import\s*\(|new URL\s*\()\s*['"](\.[^'"]+)['"]''',p.read_text()):
   q=p.parent/rel
   if q.is_file():add(q)
add(REPO/'infra/security/testing/semgrep-linux-web.mjs')
for folder in ['infra/security/policy/versions','infra/security/manager-v2/policies','infra/security/manager-v2/fixtures']:
 for p in (REPO/folder).glob('*.json'):add(p)
for manifest in ['command-parent-baseline-v1.json','gitleaks-parent-baseline-v1.json']:
 for name in json.loads((REPO/'infra/security/policy/versions'/manifest).read_text())['sourceHashes']:add(REPO/name)
lock=json.loads((REPO/'infra/security/scanner-tools.json').read_text());add(REPO/'infra/security/scanner-tools.json')
manifest={};stream=io.BytesIO()
with tarfile.open(fileobj=stream,mode='w:gz') as tar:
 for p in sorted(files):
  b=p.read_bytes();name=str(p.relative_to(REPO));manifest[name]=hashlib.sha256(b).hexdigest()
  t=tarfile.TarInfo(name);t.size=len(b);tar.addfile(t,io.BytesIO(b))
payload=base64.b64encode(stream.getvalue()).decode();entry=(REPO/'infra/security/testing/semgrep-ssh-entry.py').read_text()
key=pathlib.Path.home()/'.ssh/security-manager-v2-semgrep'
assert key.is_file() and not key.is_symlink() and key.stat().st_uid==os.getuid() and not key.stat().st_mode&0o077
pub=subprocess.check_output(['/usr/bin/ssh-keygen','-y','-f',str(key)],text=True).strip().split();assert pub[0]=='ssh-ed25519'
line='restrict,command="/usr/bin/python3 -I '+ROOT+'/ssh-entry.py" '+' '.join(pub[:2])+' security-manager-v2-semgrep-fixed\n'
script=r'''
import pathlib,os,subprocess,shutil,json,hashlib,tarfile,io,base64,pwd,grp,stat
assert os.getuid()==0 and os.uname().nodename=='devops' and os.uname().machine=='aarch64'
for db in ['passwd','group']:assert subprocess.run(['getent',db,'security-semgrep'],stdout=subprocess.DEVNULL).returncode==2
root=pathlib.Path(ROOT);home=pathlib.Path(HOME)
assert not root.exists() and not home.exists()
assert shutil.disk_usage('/var/tmp').free>1024**3
mem=next(int(l.split()[1])*1024 for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'));assert mem>1024**3
assert os.stat('/run/docker.sock').st_mode&0o777==0o660
# Locate the already pinned offline bundle through the existing Jenkins volume; read only.
pods=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','pods','-l','app=jenkins','-o','json']))['items']
v=next(v for v in pods[0]['spec']['volumes'] if 'persistentVolumeClaim'in v)
pvc=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','pvc',v['persistentVolumeClaim']['claimName'],'-o','json']))
pv=json.loads(subprocess.check_output(['kubectl','get','pv',pvc['spec']['volumeName'],'-o','json']))
src=pathlib.Path(pv['spec'].get('hostPath',pv['spec'].get('local',{}))['path'])/'platform-security/20261027'
rows=[e for e in LOCK['files'] if e['path']=='semgrep/semgrep-core' or e['path'].startswith('semgrep/libs/')]
assert len(rows)==27
for e in rows:
 p=src/e['path'];assert p.is_file() and not p.is_symlink() and p.stat().st_size==e['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==e['sha256']
subprocess.run(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir',HOME,'--shell','/bin/sh','security-semgrep'],check=True)
a=pwd.getpwnam('security-semgrep');uid,gid=a.pw_uid,a.pw_gid
assert uid not in [0,24021,24022,65534] and gid not in [0,988,24021,24022]
assert subprocess.check_output(['id','-G','security-semgrep'],text=True).strip()==str(gid)
assert subprocess.check_output(['passwd','-S','security-semgrep'],text=True).split()[1]=='L'
s=subprocess.run(['sudo','-n','-l','-U','security-semgrep'],capture_output=True,text=True)
assert 'not allowed to run sudo' in s.stdout+s.stderr
root.mkdir(mode=0o755);home.mkdir(mode=0o755)
package=root/'package';package.mkdir(mode=0o755)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD)),mode='r:gz') as tar:
 assert {m.name for m in tar.getmembers()}==set(MANIFEST) and len(tar.getmembers())==len(MANIFEST)
 for m in tar.getmembers():
  q=pathlib.PurePosixPath(m.name);assert m.isfile() and not q.is_absolute() and '..'not in q.parts and m.size<1024**2
  b=tar.extractfile(m).read();assert hashlib.sha256(b).hexdigest()==MANIFEST[m.name]
  p=package/q;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(0o444)
for d,_,_ in os.walk(package):pathlib.Path(d).chmod(0o555)
for e in rows:
 p=root/e['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src/e['path'],p);p.chmod(0o555 if e['path'].endswith('semgrep-core') else 0o444)
for d,_,_ in os.walk(root/'semgrep'):pathlib.Path(d).chmod(0o555)
shutil.copyfile(package/'infra/security/scan-rules.json',root/'rules.json');(root/'rules.json').chmod(0o444)
sources=[]
fixtures={'clean':b'class Safe { void run() { System.out.println("synthetic"); } }\n',
'controlled-finding':b'import javax.crypto.Cipher; class Unsafe { void run(String input) throws Exception { Runtime.getRuntime().exec(input); Cipher.getInstance("DES"); } }\n'}
for case,b in fixtures.items():
 source=root/('source-'+case);source.mkdir(mode=0o755);(source/'Main.java').write_bytes(b);(source/'Main.java').chmod(0o444)
 # Genuine disposable Git commit binds the passive source; source itself has no .git or hooks.
 build=root/'fixture-build';build.mkdir(mode=0o700);(build/'Main.java').write_bytes(b)
 env={'PATH':'/usr/bin:/bin','HOME':str(build),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
 def git(*argv):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*argv],cwd=build,env=env,stderr=subprocess.PIPE,timeout=7)
 git('init','--quiet');git('add','Main.java');git('-c','user.name=Validation Fixture','-c','user.email=validation@example.invalid','commit','--quiet','-m','Fixed non-production Java fixture')
 rev=git('rev-parse','HEAD').decode().strip();assert git('show',rev+':Main.java')==b;shutil.rmtree(build);source.chmod(0o555)
 binding=[{'path':'Main.java','bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}];st=source.stat()
 sources.append({'case':case,'projectId':'java-fixture','profile':'java-web','sourceDir':str(source),'sourceRevision':rev,'inode':st.st_ino,'device':st.st_dev,'fileManifestDigest':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
out=root/'outputs';out.mkdir(mode=0o700);os.chown(out,uid,gid)
approval={'schemaVersion':1,'scope':'SYNTHETIC_NON_RELEASE_SEMGREP_SCAN','workspace':ROOT,'executionUid':uid,'executionGid':gid,'outputRoot':str(out),'sources':sources,
 'tool':{'path':str(root/'semgrep/semgrep-core'),'libraryDirectory':str(root/'semgrep/libs'),'version':LOCK['versions']['semgrep']},'rules':{'path':str(root/'rules.json')}}
for n,b in [('semgrep-approval.json',json.dumps(approval)),('package-manifest.json',json.dumps(MANIFEST)),('ssh-entry.py',ENTRY)]:
 (root/n).write_text(b);(root/n).chmod(0o444)
ssh=home/'.ssh';ssh.mkdir(mode=0o750);os.chown(ssh,0,gid)
p=ssh/'authorized_keys';p.write_text(LINE);os.chown(p,0,gid);p.chmod(0o640)
cmd=['setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','--no-new-privs','--bounding-set=-all','env','-i','PATH=/usr/bin:/bin','LD_LIBRARY_PATH='+str(root/'semgrep/libs'),str(root/'semgrep/semgrep-core'),'-version']
v=subprocess.run(cmd,capture_output=True,text=True,timeout=8);assert v.returncode==0 and LOCK['versions']['semgrep'] in v.stdout
print(json.dumps({'account':{'name':a.pw_name,'uid':uid,'gid':gid,'groups':[gid],'sudo':False,'passwordLocked':True},'workspace':ROOT,'sources':sources,'toolVersion':v.stdout.strip(),'toolSha256':next(e['sha256'] for e in rows if e['path'].endswith('semgrep-core')),'toolFiles':len(rows),'packageFiles':len(MANIFEST),'sourceBundle':str(src),'sshdChanged':False,'dockerAPIUsed':False,'scanExecuted':False,'memoryAvailable':mem}))
'''
prefix='ROOT='+repr(ROOT)+'\nHOME='+repr(HOME)+'\nLOCK='+repr(lock)+'\nMANIFEST='+repr(manifest)+'\nPAYLOAD='+repr(payload)+'\nENTRY='+repr(entry)+'\nLINE='+repr(line)+'\n'
assert not (HERE/'installed.json').exists()
x=json.loads(api['remote']('sudo -n python3 -',prefix+script,timeout=100))
with (HERE/'installed.json').open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(x))
