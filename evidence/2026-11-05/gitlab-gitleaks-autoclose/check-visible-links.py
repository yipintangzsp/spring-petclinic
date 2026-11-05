"""Actual authenticated Jenkins HTTP reads plus localhost PASS/FAIL history."""
import json,runpy,shlex,urllib.request,datetime
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
checks=[]
for path in ['/job/security-gitlab-push-demo/4/api/json','/job/security-gitlab-push-demo/4/artifact/evidence/jenkins-gitleaks-receipt.json']:
 r=json.loads(p['m']['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(p['NODE']),json.dumps({'path':path,'method':'GET','timeout':12000}),25))
 assert r['status']==200
 data=json.loads(r['body'])
 if 'artifact' in path:assert data['policyDecision']=='PASS' and data['evaluationCount']==1 and data['scannerExitCode']==0
 else:assert data['result']=='SUCCESS' and data['number']==4
 checks.append({'url':'http://jenkins.devops.local'+path,'http':r['status'],'authenticatedRead':True})
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with op.open('http://security.devops.local:17862/api/runs',timeout=5) as r:runs=json.load(r)['runs']
real=[v for v in runs if v.get('scannerExecuted') is True and v.get('evidenceClass')=='REAL' and v.get('state')=='COMPLETED']
clean=next(v for v in real if v['scenarioId']=='clean' and v['policyDecision']=='PASS')
finding=next(v for v in real if v['scenarioId']=='controlled-finding' and v['policyDecision']=='FAIL')
x={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'jenkins':checks,
 'existingWebClean':{'runId':clean['runId'],'policy':clean['policyDecision'],'class':'REAL'},
 'existingWebFinding':{'runId':finding['runId'],'policy':finding['policyDecision'],'class':'REAL'},
 'newJenkinsResultVisibleIn':'Pipeline Overview HTML and authenticated Jenkins artifact API',
 'newJenkinsResultNotForgedAsWebRequest':True,'browserClick':'NOT_TESTED'}
with (OUT/'visible-links.json').open('x') as f:json.dump(x,f,indent=2)
print(json.dumps(x))
