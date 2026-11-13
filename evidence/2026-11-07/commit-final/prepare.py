import pathlib,runpy,json,shlex,sys,secrets,time,tempfile,os,hashlib,re
sys.dont_write_bytecode=True
root=pathlib.Path.cwd();h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
groovy=p['PREFIX']+r'''
def u=api('/users/4');assert !u.is_admin&&u.state=='active';def ms=api('/users/4/memberships');assert ms.size()==1&&ms[0].source_id==12&&ms[0].access_level==30
def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo');assert !d.isBuilding()&&d.lastBuild.number==10&&d.nextBuildNumber==11
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105';assert api('/projects/12/hooks/4').push_events_branch_filter=='main'
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/users/4/personal_access_tokens').openConnection();c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='POST';c.doOutput=true;c.setRequestProperty('Content-Type','application/json');c.connectTimeout=4000;c.readTimeout=8000;c.outputStream.withCloseable{it.write(JsonOutput.toJson([name:'commit-final-read',scopes:['read_repository'],expires_at:java.time.LocalDate.now(java.time.ZoneOffset.UTC).plusDays(1).toString()]).bytes)};assert c.responseCode==201;println(c.inputStream.text)
'''
# Reuse the original immutable validation package closure, plus the new source runner.
files=set()
def add(f):
 f=f.resolve();assert f.is_relative_to(root)and f.is_file()
 if f in files:return
 files.add(f)
 if f.suffix=='.mjs':
  for rel in re.findall(r'''(?:from\s*|import\s*\(|new URL\s*\()\s*['"](\.[^'"]+)['"]''',f.read_text()):
   q=f.parent/rel
   if q.is_file():add(q)
add(root/'infra/security/manager-v2/ci/commit-run.mjs')
for folder in ['infra/security/policy/versions','infra/security/manager-v2/policies','infra/security/manager-v2/fixtures']:
 for f in (root/folder).glob('*.json'):add(f)
add(root/'infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs')
for name in json.loads((root/'infra/security/policy/versions/gitleaks-parent-baseline-v1.json').read_text())['sourceHashes']:add(root/name)
for name in ['ci/source-snapshot.py','ci/commit-source-entry.py','ci/source-projects.json']:add(root/'infra/security/manager-v2'/name)
reuse=json.loads((root/'evidence/2026-11-07/real-commit-largefile/existing-package.json').read_text())['files']
assert all(f.is_relative_to(root/'infra/security')or str(f.relative_to(root))in reuse for f in files)
package={str(f.relative_to(root)):f.read_text()for f in sorted(files)if f.is_relative_to(root/'infra/security')}
reuseHashes={name:row['sha256']for name,row in reuse.items()}
cap=secrets.token_hex(32)
code=r'''
import pathlib,json,sys,subprocess,urllib.parse,os,time,hashlib
x=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-final-20261107');assert not r.exists();r.mkdir(mode=0o755);(r/'outputs').mkdir(mode=0o700);os.chown(r/'outputs',24021,24021)
q=subprocess.run(['kubectl','exec','-i','-n','ns-devops','deploy/github-webhook-relay','--','node','--max-old-space-size=24','-e',x['node']],input=json.dumps({'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':x['groovy']}),'timeout':25000}),capture_output=True,text=True,timeout=40);assert q.returncode==0;reply=json.loads(q.stdout);assert reply['status']==200;token=json.loads(reply['body'].splitlines()[0]);assert token['user_id']==4 and token['scopes']==['read_repository']
(r/'read-token').write_text(token['token']);os.chown(r/'read-token',0,24021);(r/'read-token').chmod(0o440)
(r/'askpass.py').write_text("#!/usr/bin/python3\nimport pathlib,sys\nprint('oauth2'if 'username'in sys.argv[1].lower()else pathlib.Path('/var/tmp/security-manager-gitleaks-final-20261107/read-token').read_text())\n");(r/'askpass.py').chmod(0o555)
(r/'source-config.json').write_bytes(pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107/source-config.json').read_bytes());(r/'source-config.json').chmod(0o444)
prep={'triggerBase':'a69104ba1bf88b74cc57a420888ee692b88c8c48','triggerCommit':'a69104ba1bf88b74cc57a420888ee692b88c8c48','rootTreeOid':'5a7c0d974f94a216a36dffeeeb8dc0cf2a35949b','branch':'security-demo/gitlab-push-20261105','pushExecuted':False}
(r/'credential-metadata.json').write_text(json.dumps({'readTokenId':token['id']}));(r/'credential-metadata.json').chmod(0o444)
package=r/'package';package.mkdir(mode=0o755);manifest={}
for name,text in x['package'].items():
 rel=pathlib.PurePosixPath(name);assert not rel.is_absolute()and '..'not in rel.parts;f=package/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text);f.chmod(0o444);manifest[name]=hashlib.sha256(f.read_bytes()).hexdigest()
for name,h in x['reuseHashes'].items():
 src=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/package')/name;st=src.lstat();assert src.resolve()==src and st.st_uid==0 and not st.st_mode&0o022;data=src.read_bytes();assert hashlib.sha256(data).hexdigest()==h
 dest=package/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);dest.chmod(0o444);manifest[name]=h
for d,_,_ in os.walk(package):pathlib.Path(d).chmod(0o555)
import importlib.util
spec=importlib.util.spec_from_file_location('source',package/'infra/security/manager-v2/ci/source-snapshot.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=json.loads((r/'source-config.json').read_text());budgetScope={'projectId':'python-fixture','commitSha':prep['triggerCommit']};limits=m.project_limits(json.loads((package/'infra/security/manager-v2/ci/source-projects.json').read_text()),'python-fixture',prep['triggerCommit'],budgetScope)
oldroot=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105');oldapproval=json.loads((oldroot/'approval.json').read_text());approval={'schemaVersion':1,'scope':'REAL_COMMIT_SNAPSHOT','workspace':str(r),'executionUid':24021,'outputRoot':str(r/'outputs'),'projectId':'python-fixture','profile':'python-api','commitSha':prep['triggerCommit'],'rootTreeOid':prep['rootTreeOid'],'sourceRepository':'http://gitlab.devops.local/root/petclinic-platform.git','gitRemote':base['gitRemote'],'branch':base['branch'],'expiresAt':int(time.time()*1000)+3600000,'limits':limits,'budgetScope':budgetScope,'tool':oldapproval['tool']}
for name,body in [('approval.json',approval),('package-manifest.json',manifest)]:f=r/name;f.write_text(json.dumps(body));f.chmod(0o444)
# Backup and add fixed source dispatch, preserving the entire old implementation.
f=oldroot/'ssh-entry.py';old=f.read_text();backup=oldroot/'ssh-entry.before-commit-final-20261107.py';assert not backup.exists();backup.write_text(old);backup.chmod(0o444);assert 'SSH_ORIGINAL_COMMAND'in old and 'commit-v1'not in old
prefix="import os as _source_os\nif _source_os.environ.get('SSH_ORIGINAL_COMMAND','').startswith('commit-v1 '):_source_os.execv('/usr/bin/python3',['/usr/bin/python3','-I','/var/tmp/security-manager-gitleaks-final-20261107/package/infra/security/manager-v2/ci/commit-source-entry.py'])\n";f.write_text(prefix+old);f.chmod(0o444)
f=pathlib.Path('/usr/local/libexec/security-manager-ci-dispatch.py');assert not f.exists();f.write_text(x['wrapper']);f.chmod(0o555)
keys=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys');oldkeys=keys.read_text();st=keys.stat();oldcmd='command="/usr/bin/python3 -I /usr/local/libexec/security-gitleaks-ci-proof.py"';lines=oldkeys.splitlines(True);assert sum('security-gitleaks-demo-ssh'in l for l in lines)==1
new=''.join(l.replace(oldcmd,'command="/usr/bin/python3 -I /usr/local/libexec/security-manager-ci-dispatch.py"')if 'security-gitleaks-demo-ssh'in l else l for l in lines);assert new!=oldkeys
keybackup=keys.with_name('authorized_keys.before-commit-final-20261107');assert not keybackup.exists();keybackup.write_text(oldkeys);keybackup.chmod(0o600);keys.write_text(new);os.chown(keys,st.st_uid,st.st_gid);keys.chmod(st.st_mode&511)
f=pathlib.Path('/var/lib/security-gitleaks/manager-ci-capability.json');assert not f.exists();f.write_text(json.dumps({'token':x['ciToken']}));os.chown(f,0,24021);f.chmod(0o440)
d=pathlib.Path('/var/lib/security-gitleaks/ci-channel');d.mkdir(mode=0o710);os.chown(d,1000,24021)
meta={**prep,'readTokenId':token['id'],'scannerKeysBackup':str(keybackup),'sourceEntryBackup':str(backup),'sourceEntryBeforeSha256':hashlib.sha256(old.encode()).hexdigest(),'scannerKeysBeforeSha256':hashlib.sha256(oldkeys.encode()).hexdigest(),'packageFiles':len(manifest),'limits':limits,'budgetScope':budgetScope,'expiryMs':approval['expiresAt'],'sourceRemote':base['gitRemote'],'uid':24021,'buildId':11};(r/'deployment-metadata.json').write_text(json.dumps(meta));(r/'deployment-metadata.json').chmod(0o444);print(json.dumps(meta))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps({'node':p['NODE'],'groovy':groovy,'package':package,'reuseHashes':reuseHashes,'wrapper':(root/'infra/security/manager-v2/ci/ssh-dispatch.py').read_text(),'ciToken':cap}),timeout=200))
state=pathlib.Path(tempfile.gettempdir())/('security-v2-view-'+str(os.getuid())+'-'+hashlib.sha256(str((root/'infra/security/manager-v2/view').resolve()).encode()).hexdigest()[:12]);assert state.is_dir();assert not(state/'ci-claim.json').exists()
fd=os.open(root/'.devsecops/security-view-ci-capability-v1.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w')as f:json.dump({'token':cap,'projectId':'python-fixture','commitSha':x['triggerCommit'],'buildId':11,'expiresAt':x['expiryMs'],'stateDirectory':str(state),'retryOf':'web-9bd5f65d-f047-4261-aa73-55224f3328cb'},f)
with(h/'prepared.json').open('x')as f:json.dump({**x,'localSocket':str(state/'ci.sock')},f,indent=2)
print(json.dumps({**x,'localSocket':str(state/'ci.sock'),'credentialContentsExported':False}))
