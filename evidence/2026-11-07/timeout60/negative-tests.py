import pathlib,json,runpy,shlex,urllib.request,urllib.error,os
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');prep=json.loads((h/'prepared.json').read_text());base='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}));cred=json.loads(pathlib.Path('.devsecops/security-view-project-access-v1.json').read_text());admin={'Authorization':'Bearer '+cred['operatorToken']}
def api(path,v=None):
 heads=admin.copy()
 if v is not None:heads.update({'Origin':base,'Content-Type':'application/json','X-CSRF-Token':json.load(op.open(base+'/api/plugins'))['csrfToken']})
 with op.open(urllib.request.Request(base+path,headers=heads,data=None if v is None else json.dumps(v).encode()),timeout=8)as r:return json.load(r)
v={'projectId':'python-fixture','sourceRepository':'http://gitlab.devops.local/root/petclinic-platform.git','commitSha':prep['triggerCommit'],'ciProvider':'jenkins','jobId':'security-gitlab-push-demo','buildId':12,'trigger':'gitlab-webhook','pluginId':'gitleaks','scenarioId':'clean'}
code=r'''
import subprocess,json,sys,os
v=json.load(sys.stdin);r=subprocess.run(['setpriv','--reuid=24021','--regid=24021','--clear-groups','--no-new-privs','env','SSH_ORIGINAL_COMMAND=manager-ci-v1','python3','-I','/usr/local/libexec/security-manager-ci-dispatch.py'],input=json.dumps(v),capture_output=True,text=True,timeout=12)
print(json.dumps({'exitCode':r.returncode,'result':json.loads(r.stdout)}))
'''
def invoke(value):return json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(value),timeout=20))
results=[]
for patch in [{'projectId':'java-sbom-demo'},{'pluginId':'sbom'},{'scenarioId':'controlled-finding'},{'path':'/tmp'},{'commitSha':'0'*40}]:
 r=invoke({**v,**patch});assert r['exitCode']==1 and r['result'].get('error')in ['CI_SCOPE_REJECTED','CI_FIELDS_REJECTED'];results.append({'case':next(iter(patch)),'rejected':True})
original=api('/api/config');s=json.loads(json.dumps(original['settings']));s['plugins']['gitleaks']['enabled']=False;api('/api/config',{'revision':original['revision'],'settings':s})
try:r=invoke(v);assert r['result']['state']=='DISABLED'and r['result']['scannerExecuted']is False;results.append({'case':'global-plugin-off','noScanner':True})
finally:cur=api('/api/config');api('/api/config',{'revision':cur['revision'],'settings':original['settings']})
proj=api('/api/projects/python-fixture/config');api('/api/projects/python-fixture/config',{'revision':proj['revision'],'sbomEnabled':False})
try:r=invoke(v);assert r['result']['state']=='DISABLED';results.append({'case':'project-off','noScanner':True})
finally:cur=api('/api/projects/python-fixture/config');api('/api/projects/python-fixture/config',{'revision':cur['revision'],'sbomEnabled':True})
cap=json.loads(pathlib.Path('.devsecops/security-view-ci-capability-v1.json').read_text());assert not(pathlib.Path(cap['stateDirectory'])/'ci-claim.json').exists()
with(h/'negative-tests.json').open('x')as f:json.dump({'cases':results,'claimCreated':False,'newScans':0,'defaultsRestored':True},f,indent=2)
print(json.dumps({'passed':len(results),'newScans':0,'claimCreated':False,'defaultsRestored':True}))
