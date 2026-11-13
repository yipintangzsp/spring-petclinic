"""One real web generation only; no automatic retry."""
import pathlib,urllib.request,urllib.error,json,time,datetime,hashlib
HERE=pathlib.Path(__file__).resolve().parent;BASE='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(p,h={}):
 with op.open(urllib.request.Request(BASE+p,headers=h),timeout=10)as r:return r.status,r.read()
def js(p,h={}):return json.loads(get(p,h)[1])
assert json.loads((HERE/'official-artifact-checksums.json').read_text())['status']=='VERIFIED'
prior=json.loads((HERE/'real-result.json').read_text());assert prior['executionDiagnostic']['generationInvocations']==0 and prior['executionDiagnostic']['error']=='LINUX_RESOURCE_BUDGET_BLOCKED'
assert json.loads((HERE/'resource-admission.json').read_text())['admitted']
p=js('/api/sbom/session')['projects'][0];auth={'X-Project-Token':p['projectToken']};caps=js('/api/plugins');assert next(v for v in caps['plugins']if v['pluginId']=='sbom')['state']=='READY'
assert not any(r['state']in ['RUNNING','QUEUED']for r in js('/api/runs',auth)['runs'])
config=js('/api/config');assert config['settings']['enabled']and config['settings']['plugins']['sbom']['enabled']
with(HERE/'admitted-generation-marker.json').open('x')as f:json.dump({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'maximumFormalGeneration':1,'sourceArtifactSha256':'cac4cdce5296a6d6bc31477e9a7feca0a30d9797129da11c9c9d8883a4c55cc2'},f)
req=urllib.request.Request(BASE+'/api/run',data=json.dumps({'pluginId':'sbom','scenarioId':'clean','projectId':p['projectId']}).encode(),headers={'Origin':BASE,'Content-Type':'application/json','X-CSRF-Token':caps['csrfToken'],**auth})
with op.open(req,timeout=10)as response:assert response.status==202;created=json.load(response)
with(HERE/'admitted-submitted.json').open('x')as f:json.dump(created,f,indent=2)
print(json.dumps({'submittedOnce':True,'runId':created['runId']}),flush=True)
for _ in range(180):
 r=js('/api/runs/'+created['runId'],auth)
 if r['state']not in ['RUNNING','QUEUED']:break
 time.sleep(.5)
with(HERE/'admitted-real-result.json').open('x')as f:json.dump(r,f,indent=2)
print(json.dumps({k:r.get(k)for k in ['runId','state','reason','scannerExitCode','policyDecision','evaluationCount','resultDigest','componentCount','sbomSha256','executionDiagnostic','lokiDelivery']}),flush=True)
if r['state']!='COMPLETED':raise SystemExit('Formal generation failed; no retry allowed')
assert r['evidenceClass']=='REAL'and r['evaluationCount']==1 and r['policyDecision']=='PASS'and r['scannerExitCode']==0
assert r['sourceArtifactSha256']=='cac4cdce5296a6d6bc31477e9a7feca0a30d9797129da11c9c9d8883a4c55cc2'
url='/api/projects/'+p['projectId']+'/runs/'+r['runId']+'/sbom';status,raw=get(url,auth);bom=json.loads(raw)
assert status==200 and hashlib.sha256(raw).hexdigest()==r['sbomSha256']and bom['bomFormat']=='CycloneDX'and bom['specVersion']=='1.6'and len(bom['components'])==r['componentCount']
assert any(x['consumerId']=='local-evidence'and x['deliveryDecision']=='DELIVERED_LOCAL_ONLY'for x in r['router'])
for path,h in [(url,{}),(url,{'X-Project-Token':'different-project-identity'}),(url.replace('/java-sbom-demo/','/other-project/'),auth),('/api/runs/'+r['runId'],{})]:
 try:get(path,h);raise AssertionError('UNAUTHORIZED_PROJECT_READ')
 except urllib.error.HTTPError as e:assert e.code==403
assert js('/api/runs/'+r['runId'],auth)==r
assert js('/api/config')==config
with(HERE/'generated.cdx.json').open('xb')as f:f.write(raw)
x={'runId':r['runId'],'projectId':r['projectId'],'sourceArtifactSha256':r['sourceArtifactSha256'],'sbomSha256':r['sbomSha256'],'format':bom['bomFormat'],'specVersion':bom['specVersion'],'componentCount':len(bom['components']),'policyDecision':r['policyDecision'],'policyEvaluationCount':r['evaluationCount'],'resultDigest':r['resultDigest'],'scannerExitCode':r['scannerExitCode'],'durationMs':r['durationMs'],'router':r['router'],'lokiDelivery':r.get('lokiDelivery'),'downloadApi':url,'projectReadDenials':4,'browserClick':'NOT_TESTED','harborCandidateSbomLink':'UNVERIFIED','release':0,'rollout':0}
with(HERE/'acceptance.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x),flush=True)
