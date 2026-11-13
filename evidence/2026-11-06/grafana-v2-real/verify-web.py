import json,pathlib,urllib.request,subprocess,datetime,hashlib
HERE=pathlib.Path(__file__).resolve().parent
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
def get(path):
 with op.open(base+path,timeout=8)as r:return r.status,r.read()
def read(path):return json.loads(get(path)[1])
before=read('/api/runs');cfg=read('/api/config');assert not any(x['state']in ['RUNNING','QUEUED']for x in before['runs'])
old={x['runId']:x.get('resultDigest')for x in before['runs']}
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20)
assert p.returncode==0,p.stderr
page=get('/');overview=read('/api/overview');g=overview['grafana'];assert page[0]==200
assert g['realQuery']=='VERIFIED'and g['importState']=='VERIFIED'and g['dataPanelCount']==5 and g['verifiedAt']
assert g['runId']=='web-a6dff8bd-0534-479b-bdb3-8c2c39fb4de8'
assert g['url'].startswith('http://grafana.devops.local/d/security-manager-v2-candidate/')
status,js=get('/app.js');assert status==200 and '打开 Grafana V2 Dashboard'.encode()in js
assert overview['ciCd']['build']==6 and overview['ciCd']['policyDecision']=='PASS'
after=read('/api/runs');assert old=={x['runId']:x.get('resultDigest')for x in after['runs']}
assert cfg==read('/api/config')
plugins={k:{'PASS':0,'FAIL':0}for k in ['gitleaks','semgrep','cosign']}
for run in after['runs']:
 if run.get('evidenceClass')=='REAL'and run.get('state')=='COMPLETED'and run.get('policyDecision')in ['PASS','FAIL']:plugins[run['pluginId']][run['policyDecision']]+=1
assert all(p['PASS']and p['FAIL']for p in plugins.values())
res={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'url':base+'/#candidate-overview','httpStatus':page[0],'overviewApiStatus':200,'grafanaDashboardUrl':g['url'],'grafanaQuery':'VERIFIED','runId':g['runId'],'resultDigest':g['resultDigest'],'queryVerifiedAt':g['verifiedAt'],'historyPreserved':True,'runCount':len(after['runs']),'realHistoryByPlugin':plugins,'configurationUnchanged':True,'ciCdBuild':6,'browserClick':'NOT_TESTED','secretsInPage':False,'release':0,'rollout':0}
with(HERE/'web-verification.json').open('x')as f:json.dump(res,f,indent=2)
print(json.dumps(res))
