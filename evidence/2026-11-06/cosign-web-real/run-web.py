"""Two controlled offline verifications through the existing Web endpoint, never direct result injection."""
import urllib.request,json,time,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent;BASE='http://security.devops.local:17862';opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(path,body=None,headers={}):
 r=opener.open(urllib.request.Request(BASE+path,data=json.dumps(body).encode() if body else None,headers=headers),timeout=8)
 return json.load(r)
scenario=sys.argv[1];assert scenario in ['clean','controlled-finding']
path=HERE/('web-'+scenario+'.json');assert not path.exists()
c=request('/api/plugins');assert next(p for p in c['plugins'] if p['pluginId']=='cosign')['state']=='READY'
r=request('/api/run',{'pluginId':'cosign','scenarioId':scenario},{'Origin':BASE,'Content-Type':'application/json','X-CSRF-Token':c['csrfToken']})
print(json.dumps({'submitted':r}),flush=True)
for _ in range(65):
 x=request('/api/runs/'+r['runId'])
 if x['state'] not in ['QUEUED','RUNNING']:break
 time.sleep(.5)
with path.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(x),flush=True)
assert x['state']=='COMPLETED' and x['evidenceClass']=='REAL' and x['scannerExecuted'] is True,x.get('reason')
assert x['evaluationCount']==1 and x['policyDecision']==('PASS' if scenario=='clean' else 'FAIL')
assert x['scannerExitCode']==(0 if scenario=='clean' else 1)
assert x['verificationStatus']==('VERIFIED' if scenario=='clean' else 'REJECTED')
assert request('/api/runs/'+r['runId'])==x
