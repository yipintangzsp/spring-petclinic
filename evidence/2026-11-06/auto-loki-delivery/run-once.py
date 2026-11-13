"""Exactly one Web request. No manual Consumer call or Loki push in this script."""
import json,pathlib,subprocess,urllib.request,time,datetime
HERE=pathlib.Path(__file__).resolve().parent
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
def get(path):
 with op.open(base+path,timeout=8)as r:return json.load(r)
def save(name,x):
 with(HERE/name).open('x')as f:json.dump(x,f,indent=2)
before=get('/api/runs');assert not any(r['state']in ['RUNNING','QUEUED']for r in before['runs'])
control=get('/api/config');assert control['settings']['enabled']and control['settings']['plugins']['semgrep']['enabled']and control['settings']['securityLevel']=='standard'
save('before-web.json',{'configuration':control,'existingRuns':[{'runId':r['runId'],'resultDigest':r.get('resultDigest'),'state':r['state']}for r in before['runs']]})
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
session=get('/api/plugins');assert next(p for p in session['plugins']if p['pluginId']=='semgrep')['state']=='READY'
# Exclusive marker prevents accidental second invocation, even if the HTTP response is lost.
save('single-request-marker.json',{'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pluginId':'semgrep','scenarioId':'clean','maximumWebRequests':1})
req=urllib.request.Request(base+'/api/run',data=json.dumps({'pluginId':'semgrep','scenarioId':'clean'}).encode(),headers={'Origin':base,'Content-Type':'application/json','X-CSRF-Token':session['csrfToken']})
with op.open(req,timeout=8)as response:
 assert response.status==202;created=json.load(response)
save('submitted.json',created);print(json.dumps({'submittedOnce':True,'runId':created['runId']}),flush=True)
for _ in range(100):
 run=get('/api/runs/'+created['runId'])
 if run['state']not in ['RUNNING','QUEUED']:break
 time.sleep(.5)
save('real-run.json',run)
assert run['state']=='COMPLETED'and run['evidenceClass']=='REAL'and run['policyDecision']=='PASS'and run['scannerExitCode']==0 and run['evaluationCount']==1,'REAL_CLEAN_NOT_COMPLETED'
l=run.get('lokiDelivery',{})
assert l.get('automatic')is True and l.get('state')=='DELIVERED'and l.get('pushHttpStatus')==204 and l.get('queryState')=='VERIFIED','AUTOMATIC_LOKI_DELIVERY_INCOMPLETE: '+str(l.get('reason'))
assert l['runId']==run['runId']and l['resultDigest']==run['resultDigest']and l['sourceClassification']=='REAL_CONTROLLED_EXECUTION'and l['httpRequestCount']==1
assert control==get('/api/config');assert get('/api/runs/'+created['runId'])==run
with op.open(base+'/',timeout=8)as response:assert response.status==200
with op.open(base+'/app.js',timeout=8)as response:assert 'Loki 自动投递'.encode()in response.read()
save('web-acceptance.json',{'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'webRequests':1,'realScans':1,'runId':run['runId'],'pluginId':run['pluginId'],'policyDecision':run['policyDecision'],'evaluationCount':run['evaluationCount'],'resultDigest':run['resultDigest'],'automaticLokiDelivery':l,'pageHttpStatus':200,'resultPersistent':True,'configurationUnchanged':True,'browserClick':'NOT_TESTED','release':0,'rollout':0})
print(json.dumps({'runId':run['runId'],'plugin':run['pluginId'],'policy':run['policyDecision'],'exitCode':run['scannerExitCode'],'resultDigest':run['resultDigest'],'durationMs':run['durationMs'],'lokiDelivery':l}))
