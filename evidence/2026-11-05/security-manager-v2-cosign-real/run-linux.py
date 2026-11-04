"""Transfer a bounded reviewed non-secret code bundle and run approved fixtures.

No source checkout on Jenkins, no container/Pod, no production tool alteration.
"""
from pathlib import Path
import runpy,json,re,hashlib,io,tarfile,base64,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2];api=runpy.run_path(str(OUT/'inspect-production.py'))
attempt=int(sys.argv[1]) if len(sys.argv)>1 else 1;assert 1<=attempt<=3
files=set()
def add(p):
 p=p.resolve();assert p.is_relative_to(ROOT) and p.is_file() and not p.is_symlink()
 if p in files:return
 files.add(p)
 if p.suffix=='.mjs':
  for rel in re.findall(r'(?:from\s*|import\s*\(|new URL\s*\()\s*[\'\"](\.[^\'\"]+)[\'\"]',p.read_text()):
   q=(p.parent/rel).resolve()
   if q.is_file():add(q)
for n in ['core.mjs','cli.mjs','router.mjs']:add(ROOT/'infra/security/manager-v2'/n)
add(ROOT/'infra/security/testing/cosign-real-suite.mjs')
for folder in ['infra/security/policy/versions','infra/security/manager-v2/policies','infra/security/manager-v2/fixtures']:
 for p in (ROOT/folder).glob('*.json'):add(p)
add(ROOT/'infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs')
for manifest in ['gitleaks-parent-baseline-v1.json','command-parent-baseline-v1.json','cosign-parent-baseline-v1.json']:
 for n in json.loads((ROOT/'infra/security/policy/versions'/manifest).read_text())['sourceHashes']:add(ROOT/n)
stream=io.BytesIO()
with tarfile.open(fileobj=stream,mode='w:gz') as tar:
 for p in sorted(files):
  b=p.read_bytes();assert len(b)<1024**2
  info=tarfile.TarInfo(str(p.relative_to(ROOT)));info.size=len(b);info.mode=0o444;tar.addfile(info,io.BytesIO(b))
blob=stream.getvalue();assert len(blob)<512*1024
package={'classification':'REVIEWED_NON_SECRET_CODE_BUNDLE','files':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)},'tarBytes':len(blob),'tarSha256':hashlib.sha256(blob).hexdigest(),'secretsIncluded':False}
api['save']('linux-package'+(''if attempt==1 else '-attempt'+str(attempt))+'.json',package)
root=json.loads((OUT/'tool-preparation.json').read_text())['workspace']
script=r'''
import os,pathlib,json,hashlib,tarfile,base64,io,subprocess,random,string,time,shutil
root=pathlib.Path(ROOT_PATH);assert root.is_dir() and root.stat().st_uid==0
assert shutil.disk_usage(root).free>2*1024**3
assert not(root/PACKAGE_DIR).exists()
package=root/PACKAGE_DIR;package.mkdir(mode=0o755)
blob=base64.b64decode(BLOB);assert hashlib.sha256(blob).hexdigest()==PACKAGE_SHA
with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
 for m in tar.getmembers():
  rel=pathlib.PurePosixPath(m.name);assert m.isfile() and not rel.is_absolute() and '..'not in rel.parts and m.name in MANIFEST
  target=package/rel;target.parent.mkdir(parents=True,exist_ok=True);b=tar.extractfile(m).read();assert hashlib.sha256(b).hexdigest()==MANIFEST[m.name];target.write_bytes(b);target.chmod(0o444)
for d,ds,fs in os.walk(package):pathlib.Path(d).chmod(0o555)
out=root/'outputs';out.mkdir(mode=0o700,exist_ok=True);os.chown(out,65534,65534)
if ATTEMPT==1:
 home=root/'git-home';home.mkdir(mode=0o700)
 env={'PATH':'/usr/bin:/bin','HOME':str(home),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','LANG':'C'}
 chars=list(string.ascii_letters+string.digits);random.SystemRandom().shuffle(chars);fake='ghp_'+''.join(chars[:36]);sources=[]
 cases=[
  ('clean','java-fixture','java-web','Safe.java','class Safe { void run() { System.out.println("synthetic"); } }'),
  ('secret','java-fixture','java-web','Main.java','// SYNTHETIC NEVER ISSUED\nclass Main { String github_token = "'+fake+'"; }'),
  ('vulnerable','java-fixture','java-web','Unsafe.java','import javax.crypto.Cipher; class Unsafe { void run(String input) throws Exception { Runtime.getRuntime().exec(input); Cipher.getInstance("DES"); } }'),
  ('parse-error','java-fixture','java-web','Broken.java','class Broken { void {{{{{ ; class ; }'),
  ('warning','java-fixture','java-web','Command.java','class Command { void run(String input) throws Exception { Runtime.getRuntime().exec(input); } }'),
  ('service-clean','service-fixture','container-service','Worker.java','class Worker { int add(int x) { return x+1; } }'),
  ('python-only','python-fixture','python-api','app.py','print("controlled python fixture; no Java rules apply")')]
 for case,project,profile,name,text in cases:
  repo=root/('repo-'+case);repo.mkdir(mode=0o700)
  def git(args):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',*args],cwd=repo,env=env,stderr=subprocess.PIPE,timeout=10)
  git(['init','--quiet']);(repo/name).write_text(text+'\n');git(['add',name]);git(['-c','user.name=Validation Fixture','-c','user.email=validation@example.invalid','commit','--quiet','-m','Authorized disposable Semgrep/Gitleaks fixture'])
  source=root/('source-'+case);source.mkdir(mode=0o755);p=source/name;p.write_bytes((repo/name).read_bytes());p.chmod(0o444);source.chmod(0o555);st=source.stat()
  entries=[{'path':name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}]
  sources.append({'case':case,'projectId':project,'profile':profile,'sourceDir':str(source),'sourceRevision':git(['rev-parse','HEAD']).decode().strip(),'inode':st.st_ino,'device':st.st_dev,'fileManifestDigest':hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
 provenance=json.loads((root/'tool-provenance.json').read_text())
 common={'schemaVersion':1,'workspace':str(root),'executionUid':65534,'outputRoot':str(out),'sources':sources,'authorization':{'subject':'USER_REQUEST_57249cad','status':'APPROVED_CONTROLLED_NON_PRODUCTION_FIXTURES_ONLY','noProductionAccess':True}}
 for file,a in [('approval.json',{**common,'scope':'SYNTHETIC_NON_RELEASE_DIR_SCAN','tool':provenance['tool']}),('semgrep-approval.json',{**common,'scope':'SYNTHETIC_NON_RELEASE_SEMGREP_SCAN','tool':provenance['semgrep'],'rules':{'path':str(root/'rules.json')}})]:
  p=root/file;p.write_text(json.dumps(a));p.chmod(0o444)
 shutil.copyfile(package/'infra/security/scan-rules.json',root/'rules.json');(root/'rules.json').chmod(0o444)
 (root/'fake-value.sha256').write_text(hashlib.sha256(fake.encode()).hexdigest());(root/'fake-value.sha256').chmod(0o600)
else:
 fake=(root/'source-secret/Main.java').read_text().split('ghp_')[1].split(chr(34))[0];fake='ghp_'+fake
sig=json.loads((root/'signature-preparation.json').read_text());assert sig['privateDirectoryRemovedBeforeManager'] and not(root/'cosign-private').exists()
if ATTEMPT==1:
 semgrepApproval=json.loads((root/'semgrep-approval.json').read_text())
 approval={'schemaVersion':1,'scope':'SYNTHETIC_NON_RELEASE_OFFLINE_COSIGN_VERIFICATION','workspace':str(root),'executionUid':65534,'outputRoot':str(out),'tool':json.loads((root/'tool-provenance.json').read_text())['cosign'],'objects':sig['objects'],'trustIdentities':sig['trustIdentities'],'authorization':{'subject':'USER_REQUEST_57249cad','status':'APPROVED_CONTROLLED_NON_PRODUCTION_FIXTURES_ONLY'}}
 (root/'cosign-approval.json').write_text(json.dumps(approval));(root/'cosign-approval.json').chmod(0o444)
cmd=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--no-new-privs','--bounding-set=-all','env','-i','PATH=/usr/bin:/bin','HOME='+str(out),'/usr/bin/node','--max-old-space-size=256',str(package/'infra/security/testing/cosign-real-suite.mjs'),str(root),RUN_PREFIX]
start=time.time();p=subprocess.run(cmd,cwd=package,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240)
for kind,data in [('stdout',p.stdout),('stderr',p.stderr)]:
 assert fake.encode()not in data
 (root/(RUN_PREFIX+'suite.'+kind)).write_bytes(data)
record={'classification':'REAL_CONTROLLED_LINUX_EXECUTION','exit':p.returncode,'seconds':round(time.time()-start,3),'stdout':p.stdout.decode(),'stderr':p.stderr.decode(),'command':cmd,'nodeVersion':subprocess.check_output(['node','--version'],text=True).strip(),'scannedSourcesExecuted':False,'productionMutations':0,'release':0,'rollout':0}
(root/(RUN_PREFIX+'controller-result.json')).write_text(json.dumps(record))
if p.returncode==0:
 # A real absent-tool case, not only a caller-declared capability hint. Only the
 # disposable copy is renamed; original production tool is never modified.
 tool=root/'cosign';held=root/'cosign-held';assert not held.exists();tool.rename(held)
 try:
  missingCmd=cmd+['tool-missing']
  missing=subprocess.run(missingCmd,cwd=package,capture_output=True,timeout=90)
  assert fake.encode()not in missing.stdout+missing.stderr
  (root/(RUN_PREFIX+'missing-suite.stdout')).write_bytes(missing.stdout);(root/(RUN_PREFIX+'missing-suite.stderr')).write_bytes(missing.stderr)
  result={'classification':'REAL_CONTROLLED_ACTUAL_MISSING_LOCAL_TOOL','exit':missing.returncode,'stdout':missing.stdout.decode(),'stderr':missing.stderr.decode(),'command':missingCmd,'productionToolModified':False}
  (root/(RUN_PREFIX+'missing-controller-result.json')).write_text(json.dumps(result));record['actualMissingTool']=result
 finally:held.rename(tool)
print(json.dumps(record))
'''
prefix='ATTEMPT='+repr(attempt)+'\nPACKAGE_DIR='+repr('package'if attempt==1 else 'package-attempt'+str(attempt))+'\nRUN_PREFIX='+repr(''if attempt==1 else 'attempt'+str(attempt)+'-')+'\nROOT_PATH='+repr(root)+'\nBLOB='+repr(base64.b64encode(blob).decode())+'\nPACKAGE_SHA='+repr(package['tarSha256'])+'\nMANIFEST='+repr(package['files'])+'\n'
x=json.loads(api['remote']('sudo -n python3 -',prefix+script,280));api['save']('linux-controller-result'+(''if attempt==1 else '-attempt'+str(attempt))+'.json',x);print(json.dumps({'exit':x['exit'],'seconds':x['seconds'],'stdoutTail':x['stdout'][-1400:],'stderr':x['stderr'][-1800:]}))
