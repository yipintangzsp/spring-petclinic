"""HTTP acceptance for the actual GitOps result; no write/scanner endpoints."""
import concurrent.futures
import datetime
import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
OUT=Path(__file__).resolve().parent
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):return None
op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
base='http://security.devops.local:17862'
def get(url):
 try:
  with op.open(url,timeout=5) as r:return r.status,r.read(2*1024*1024)
 except urllib.error.HTTPError as e:return e.code,b''
status,body=get(base+'/');assert status==200
assert get(base+'/')==(status,body)
card=body.decode().split('<!-- GITOPS_DEMO_RESULT_BEGIN -->')[1].split('<!-- GITOPS_DEMO_RESULT_END -->')[0]
for stage in ['baseline','updated','restored']:
 v=json.loads((OUT/(stage+'.json')).read_text())
 for value in [v['expectedCommit'],v['argo']['revision'],v['configMap']['resourceVersion'],v['observedAt']]:assert value in card
assert 'VERIFIED · REAL GITOPS' in card and 'REAL CHANGE · INCOMPLETE' not in card
assert 'baseline → updated → baseline' in card and 'HISTORICAL' in card
assert 'This reverts commit' in json.loads((OUT/'verified.json').read_text())['gitlab']['commitProofs'][2]['message']
for bad in ['PRIVATE KEY-----','PRIVATE-TOKEN','COSIGN_PASSWORD','GITLAB_TOKEN']:assert bad not in card
links=re.findall('href="(http://[^\"]+)"',card)
def visit(url):
 code,_=get(url);assert code in [200,302],(url,code)
 return {'url':url,'http':code,'authenticatedUi':'NOT_TESTED'}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:nav=list(ex.map(visit,links))
status,runs=get(base+'/api/runs');assert status==200
real=[r for r in json.loads(runs)['runs'] if r.get('pluginId')=='gitleaks' and r.get('evidenceClass')=='REAL' and r.get('state')=='COMPLETED']
assert any(r.get('scenarioId')=='clean' and r.get('policyDecision')=='PASS' for r in real)
assert any(r.get('scenarioId')=='controlled-finding' and r.get('policyDecision')=='FAIL' for r in real)
status,css=get(base+'/style.css');assert status==200 and b'#gitops-demo-result' in css
result={'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'viewUrl':base+'/#pipeline-overview',
 'http':200,'refreshHttp':200,'sameRunStageValuesVisible':True,'pageSha256':hashlib.sha256(body).hexdigest(),
 'navigation':nav,'existingRealGitleaksPassFailPreserved':True,'browserClick':'NOT_TESTED',
 'PIPELINE_OVERVIEW':'VERIFIED','productionRelease':False,'productionRollout':False}
with (OUT/'page-http.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
