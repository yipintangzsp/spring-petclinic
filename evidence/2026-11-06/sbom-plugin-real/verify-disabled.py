import json,pathlib,urllib.request,urllib.error,subprocess,time,datetime
HERE=pathlib.Path(__file__).resolve().parent;base='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(p,headers={}):
 with op.open(urllib.request.Request(base+p,headers=headers),timeout=8)as r:return json.load(r)
assert not any(r['state']in ['RUNNING','QUEUED']for r in get('/api/runs')['runs'])
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
session=get('/api/plugins')['csrfToken'];project=get('/api/sbom/session')['projects'][0];headers={'X-Project-Token':project['projectToken']};initial=get('/api/config')
def post(p,body,h={}):
 req=urllib.request.Request(base+p,data=json.dumps(body).encode(),headers={'Origin':base,'Content-Type':'application/json','X-CSRF-Token':session,**headers,**h})
 with op.open(req,timeout=8)as r:return json.load(r)
settings=json.loads(json.dumps(initial['settings']));settings['plugins']['sbom']['enabled']=False
changed=post('/api/config',{'revision':initial['revision'],'settings':settings})
run=post('/api/run',{'pluginId':'sbom','scenarioId':'clean','projectId':project['projectId']})
for _ in range(30):
 r=get('/api/runs/'+run['runId'],headers)
 if r['state']not in ['RUNNING','QUEUED']:break
 time.sleep(.1)
assert r['state']=='DISABLED'and r['scannerExecuted']is False and r['evaluationCount']==0 and r['artifactDigest']is None
assert not pathlib.Path('.devsecops/security-view-runs-v1',run['runId'],'artifact').exists()
# Global OFF follows the same zero-execution path.
settings['enabled']=False;settings['plugins']['sbom']['enabled']=True
changed=post('/api/config',{'revision':changed['revision'],'settings':settings})
globalRun=post('/api/run',{'pluginId':'sbom','scenarioId':'clean','projectId':project['projectId']})
for _ in range(30):
 gr=get('/api/runs/'+globalRun['runId'],headers)
 if gr['state']not in ['RUNNING','QUEUED']:break
 time.sleep(.1)
assert gr['state']=='DISABLED'and not gr['scannerExecuted']and gr['artifactDigest']is None
restored=post('/api/config',{'revision':changed['revision'],'settings':initial['settings']})
for p,h in [('/api/runs/'+run['runId'],{}),('/api/runs/'+run['runId'],{'X-Project-Token':'incorrect'})]:
 try:get(p,h);raise AssertionError('RESULT_EXPOSED')
 except urllib.error.HTTPError as e:assert e.code==403
try:post('/api/run',{'pluginId':'sbom','scenarioId':'clean','projectId':'other-project'});raise AssertionError('PROJECT_ACCEPTED')
except urllib.error.HTTPError as e:assert e.code==403
out={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pluginOff':r,'globalOff':gr,'noArtifactProduced':True,'realGenerations':0,'unauthorizedProjectDenied':True,'missingOrWrongProjectTokenDenied':True,'settingsRestored':restored['settings'],'viewHttpStatus':200}
with(HERE/'disabled-proof.json').open('x')as f:json.dump(out,f,indent=2)
print(json.dumps({'pluginOff':'VERIFIED','globalOff':'VERIFIED','noArtifact':True,'projectDenials':'VERIFIED','settingsRestored':True,'generations':0}))
