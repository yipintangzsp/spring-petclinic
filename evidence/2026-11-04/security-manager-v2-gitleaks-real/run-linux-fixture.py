"""Trusted operator: transfer reviewed code, create disposable fake sources, run as nobody.

No production API writes, image pull, container start or network scanner invocation.
The scanner is a local dir scan of root-owned bounded synthetic snapshots only.
"""
import base64,hashlib,io,json,pathlib,re,subprocess,tarfile,sys
retry=len(sys.argv)>1 and sys.argv[1]=="retry"
O=pathlib.Path(__file__).resolve().parent
ROOT=O.parents[2]
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
files=set()
def add(p):
 p=p.resolve();assert p.is_relative_to(ROOT) and p.is_file() and not p.is_symlink()
 if p in files:return
 files.add(p)
 if p.suffix=='.mjs':
  for relative in re.findall(r'(?:from\s*|import\s*\(|new URL\s*\()\s*[\'\"](\.[^\'\"]+)[\'\"]',p.read_text()):
   q=(p.parent/relative).resolve()
   if q.is_file():add(q)
for entry in ['core.mjs','cli.mjs','router.mjs']:add(ROOT/'infra/security/manager-v2'/entry)
add(ROOT/'infra/security/testing/gitleaks-real-suite.mjs')
for folder in ['infra/security/policy/versions','infra/security/manager-v2/policies','infra/security/manager-v2/fixtures']:
 for p in (ROOT/folder).glob('*.json'):add(p)
add(ROOT/'infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs')
for name in json.loads((ROOT/'infra/security/policy/versions/gitleaks-parent-baseline-v1.json').read_text())['sourceHashes']:add(ROOT/name)
stream=io.BytesIO()
with tarfile.open(fileobj=stream,mode='w:gz') as tar:
 for p in sorted(files):
  data=p.read_bytes();assert len(data)<1024**2
  info=tarfile.TarInfo(str(p.relative_to(ROOT)));info.size=len(data);info.mode=0o444;tar.addfile(info,io.BytesIO(data))
blob=stream.getvalue()
manifest={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
package={'files':manifest,'count':len(files),'tarBytes':len(blob),'tarSha256':hashlib.sha256(blob).hexdigest(),'credentialsIncluded':False,'productionCodeExecuted':False}
with (O/('linux-package-retry.json' if retry else 'linux-package.json')).open('x') as f:json.dump(package,f,indent=2);f.write('\n')
remoteRoot=json.loads((O/'linux-tool-provenance.json').read_text())['workspace']
script=r'''
import os,pathlib,subprocess,json,hashlib,tarfile,io,base64,shutil,random,string,time
root=pathlib.Path(ROOT_PATH);assert root.is_dir() and root.stat().st_uid==0
if RETRY:
 for name in ['package','outputs','controller-results.json']:
  (root/name).rename(root/(name+'-attempt1'))
else:assert not (root/'package').exists() and not (root/'outputs').exists()
blob=base64.b64decode(PACKAGE_B64);assert hashlib.sha256(blob).hexdigest()==PACKAGE_SHA
package=root/'package';package.mkdir(mode=0o755)
with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
 members=tar.getmembers();assert len(members)<300 and sum(m.size for m in members)<4*1024**2
 for m in members:
  rel=pathlib.PurePosixPath(m.name);assert m.isfile() and not rel.is_absolute() and '..' not in rel.parts
  target=package/rel;target.parent.mkdir(parents=True,exist_ok=True);data=tar.extractfile(m).read();assert hashlib.sha256(data).hexdigest()==MANIFEST[m.name]
  target.write_bytes(data);target.chmod(0o444)
for d,ds,fs in os.walk(package):pathlib.Path(d).chmod(0o755)
out=root/'outputs';out.mkdir(mode=0o700);os.chown(out,65534,65534)
if not RETRY:
 home=root/'git-home';home.mkdir(mode=0o700)
 env={'PATH':'/usr/bin:/bin','HOME':str(home),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','LANG':'C'}
 alphabet=list(string.ascii_letters+string.digits);random.SystemRandom().shuffle(alphabet);fake='ghp_'+''.join(alphabet[:36])
 sources=[]
 for language,project,profile,text,name in [
  ('java','java-fixture','java-web','// SYNTHETIC, NEVER ISSUED BY ANY SERVICE\nString github_token = "'+fake+'";\n','Main.java'),
  ('python','python-fixture','python-api','# Disposable cross-project validation fixture\nprint("public clean fixture")\n','app.py')]:
  repo=root/('repo-'+language);repo.mkdir(mode=0o700)
  def git(args):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=repo,env=env,stderr=subprocess.PIPE,timeout=10)
  git(['init','--quiet']);(repo/name).write_text(text);git(['add',name]);git(['-c','user.name=Validation Fixture','-c','user.email=validation@example.invalid','commit','--quiet','-m','Disposable non-production source'])
  revision=git(['rev-parse','HEAD']).decode().strip();archive=git(['archive','HEAD'])
  source=root/('source-'+language);source.mkdir(mode=0o755)
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
   for m in tar.getmembers():
    assert m.isfile() and m.name==name
    f=source/name;f.write_bytes(tar.extractfile(m).read());f.chmod(0o444)
  source.chmod(0o555);st=source.stat()
  entries=[{'path':name,'sha256':hashlib.sha256((source/name).read_bytes()).hexdigest(),'bytes':(source/name).stat().st_size}]
  manifestHash=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  sources.append({'projectId':project,'profile':profile,'sourceDir':str(source),'sourceRevision':revision,'inode':st.st_ino,'device':st.st_dev,'fileManifestDigest':manifestHash})
 approval={'schemaVersion':1,'scope':'SYNTHETIC_NON_RELEASE_DIR_SCAN','workspace':str(root),'executionUid':65534,'outputRoot':str(out),'tool':json.loads((root/'tool-provenance.json').read_text())['tool'],'sources':sources}
 (root/'approval.json').write_text(json.dumps(approval));(root/'approval.json').chmod(0o444)
 (root/'fake-value.sha256').write_text(hashlib.sha256(fake.encode()).hexdigest());(root/'fake-value.sha256').chmod(0o600)
else:
 fake=(root/'source-java/Main.java').read_text().split('ghp_')[1].split(chr(34))[0];fake='ghp_'+fake
def run(mode):
 command=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--no-new-privs','--bounding-set=-all','/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME='+str(out),'/usr/bin/node','--max-old-space-size=256',str(package/'infra/security/testing/gitleaks-real-suite.mjs'),str(root/'approval.json'),mode]
 started=time.time();p=subprocess.run(command,cwd=package,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 # These streams contain status/assertions only, never source text. Native raw stays redacted.
 for label,data in [('stdout',p.stdout),('stderr',p.stderr)]:
  assert fake.encode() not in data
  (root/(mode+'.'+label)).write_bytes(data)
 return {'mode':mode,'exit':p.returncode,'durationSeconds':round(time.time()-started,3),'stdout':p.stdout.decode(),'stderr':p.stderr.decode()[-3000:],'commandIdentity':command,'identity':'uid=65534,gid=65534,groups cleared,NoNewPrivs,CapEff=0'}
records=[run('normal')]
if records[0]['exit']==0:
 try:
  (root/'gitleaks').chmod(0o444);records.append(run('tool-error'))
 finally:(root/'gitleaks').chmod(0o555)
(root/'controller-results.json').write_text(json.dumps({'executions':records,'realScope':'synthetic non-release sources; no production pod/lease/canary reexecution','release':0,'rollout':0}));print(json.dumps(records))
'''
prefix='RETRY='+repr(retry)+'\nROOT_PATH='+repr(remoteRoot)+'\nPACKAGE_B64='+repr(base64.b64encode(blob).decode())+'\nPACKAGE_SHA='+repr(package['tarSha256'])+'\nMANIFEST='+repr(manifest)+'\n'
p=subprocess.run(S+['sudo -n python3 -'],input=prefix+script,text=True,capture_output=True,timeout=120)
with (O/('linux-controller-retry.json' if retry else 'linux-controller-execution.json')).open('x') as f:json.dump({'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr},f,indent=2);f.write('\n')
print(p.stdout);print(p.stderr);raise SystemExit(p.returncode)
