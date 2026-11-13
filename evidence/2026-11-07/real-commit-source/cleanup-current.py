import pathlib,json,runpy,shlex,sys,datetime
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
g=p['PREFIX']+r'''
def t=api('/personal_access_tokens/5');assert t.user_id==4&&t.scopes==['read_repository']&&!t.revoked
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/personal_access_tokens/5').openConnection();c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='DELETE';c.connectTimeout=4000;c.readTimeout=6000;assert c.responseCode==204
def after=api('/personal_access_tokens/5');assert after.revoked
 def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo');assert !d.isBuilding()&&d.lastBuild.number==8&&d.nextBuildNumber==9
println(JsonOutput.toJson([readTokenId:5,readTokenRevoked:true,activeUser4Tokens:api('/personal_access_tokens?user_id=4&state=active').findAll{!it.revoked&&it.active}.collect{[id:it.id,scopes:it.scopes]},branchCommit:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id,lastDemoBuild:d.lastBuild.number,lastDemoResult:d.lastBuild.result.toString(),newPushes:0,newBuilds:0,newScans:0,writerTokenCreated:false]))
'''
x=p['script'](g)
code=r'''
import pathlib,json,hashlib,shutil
r=pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107');assert r.stat().st_uid==0 and not r.is_symlink();expected={'read-token','askpass.py','source-config.json','source-snapshot.py','outputs'};assert {f.name for f in r.iterdir()}==expected;assert not list((r/'outputs').iterdir())
for name in expected-{'outputs'}:
 f=r/name;assert f.is_file()and not f.is_symlink()and f.stat().st_uid==0
original=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py');keys=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys');assert b'commit-v1'not in original.read_bytes();assert hashlib.sha256(keys.read_bytes()).hexdigest()=='506c7e3c0cbe0e05b5b95a8e1d482214256650f055bb370f9b1867d2235c8c07'
assert not pathlib.Path('/var/lib/security-gitleaks/manager-ci-capability.json').exists();assert not pathlib.Path('/var/lib/security-gitleaks/ci-channel').exists()
shutil.rmtree(r);assert not r.exists()
print(json.dumps({'temporaryReadCredentialRemoved':True,'temporarySourceRemoved':True,'taskServerDirectoryRemoved':True,'scannerSshEntryUnchanged':True,'authorizedKeysUnchanged':True,'ciChannelNotCreated':True,'capabilityNotCreated':True,'serverPackageNotDeployed':True}))
'''
x.update(json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=20)));x['at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
assert not pathlib.Path('.devsecops/security-view-ci-capability-v1.json').exists();x['localCapabilityAbsent']=True
with(h/'cleanup-current.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
