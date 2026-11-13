"""Exactly one authorized web invocation; no retry or generation fallback."""
import pathlib,json,urllib.request,urllib.error,subprocess,time,datetime,hashlib
HERE=pathlib.Path(__file__).resolve().parent;base='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(p,h={}):
 with op.open(urllib.request.Request(base+p,headers=h),timeout=8)as r:return json.load(r)
assert not any(r['state']in ['RUNNING','QUEUED']for r in get('/api/runs')['runs'])
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
session=get('/api/plugins');project=get('/api/sbom/session')['projects'][0];auth={'X-Project-Token':project['projectToken']}
config=get('/api/config');assert config['settings']['enabled']and config['settings']['plugins']['sbom']['enabled']
with(HERE/'single-generation-marker.json').open('x')as f:json.dump({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'maximumActualGeneration':1},f)
req=urllib.request.Request(base+'/api/run',data=json.dumps({'pluginId':'sbom','scenarioId':'clean','projectId':project['projectId']}).encode(),headers={'Origin':base,'Content-Type':'application/json','X-CSRF-Token':session['csrfToken'],**auth})
with op.open(req,timeout=8)as r:created=json.load(r);assert r.status==202
with(HERE/'submitted.json').open('x')as f:json.dump(created,f,indent=2)
print(json.dumps({'submittedOnce':True,'runId':created['runId']}),flush=True)
for _ in range(185):
 run=get('/api/runs/'+created['runId'],auth)
 if run['state']not in ['QUEUED','RUNNING']:break
 time.sleep(.5)
with(HERE/'real-run.json').open('x')as f:json.dump(run,f,indent=2)
print(json.dumps(run),flush=True)
if run['state']!='COMPLETED':raise SystemExit('Real generation did not complete; no second invocation permitted')
assert run['evidenceClass']=='REAL'and run['evaluationCount']==1 and run['policyDecision']=='PASS'
url='/api/projects/'+project['projectId']+'/runs/'+run['runId']+'/sbom'
with op.open(urllib.request.Request(base+url,headers=auth),timeout=8)as r:raw=r.read()
bom=json.loads(raw);assert hashlib.sha256(raw).hexdigest()==run['sbomSha256']and bom['bomFormat']=='CycloneDX'and bom['specVersion']=='1.6'and len(bom['components'])==run['componentCount']
for path,h in [(url,{}),(url,{'X-Project-Token':'other-project-token'}),(url.replace('/java-sbom-demo/','/another-project/'),auth),('/api/runs/'+run['runId'],{})]:
 try:get(path,h);raise AssertionError('UNAUTHORIZED_PROJECT_READ')
 except urllib.error.HTTPError as e:assert e.code==403
assert get('/api/runs/'+run['runId'],auth)==run
assert get('/api/config')==config
with(HERE/'generated.cdx.json').open('xb')as f:f.write(raw)
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runId':run['runId'],'projectId':run['projectId'],'sourceArtifactSha256':run['sourceArtifactSha256'],'sbomSha256':run['sbomSha256'],'componentCount':run['componentCount'],'policyDecision':run['policyDecision'],'evaluationCount':run['evaluationCount'],'resultDigest':run['resultDigest'],'router':run['router'],'downloadApi':url,'rawHashMatches':True,'projectDenials':True,'singleGeneration':True,'browserClick':'NOT_TESTED','harborCandidateSbomLink':'UNVERIFIED','release':0,'rollout':0}
with(HERE/'acceptance.json').open('x')as f:json.dump(result,f,indent=2)
print(json.dumps(result))
