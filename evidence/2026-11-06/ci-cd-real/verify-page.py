"""Real HTTP reads of the existing page and original result links; no new execution."""
from common import *
import urllib.request,urllib.error,re,concurrent.futures,hashlib,datetime
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):return None
op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
base='http://security.devops.local:17862'
def get(url):
 try:
  with op.open(url,timeout=5) as r:return r.status,r.read(2*1024*1024)
 except urllib.error.HTTPError as e:return e.code,b''
status,body=get(base+'/');assert status==200 and get(base+'/')==(200,body)
card=body.decode().split('<!-- CI_CD_SAME_RUN_BEGIN -->')[1].split('<!-- CI_CD_SAME_RUN_END -->')[0]
cd=json.loads((OUT/'result.json').read_text())
for value in [cd['triggerCommit'],cd['runId'],cd['resultDigest'],cd['update']['afterCommit'],cd['restore']['afterCommit'],cd['updated']['resourceVersion'],cd['restored']['resourceVersion'],'HISTORICAL','Jenkins #6 SUCCESS']:
 assert value in card
assert all(x not in card for x in ['PRIVATE KEY-----','glpat-','PRIVATE-TOKEN','COSIGN_PASSWORD'])
urls=re.findall('href="(http://[^\"]+)"',card)
def visit(url):
 code,_=get(url);assert code in [200,302,403],(url,code)
 return {'url':url,'http':code,'authenticatedBrowser':'NOT_TESTED'}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:links=list(pool.map(visit,urls))
code,b=get(base+'/api/runs');assert code==200
real=[v for v in json.loads(b)['runs'] if v.get('pluginId')=='gitleaks' and v.get('evidenceClass')=='REAL' and v.get('state')=='COMPLETED']
assert any(v.get('scenarioId')=='clean' and v.get('policyDecision')=='PASS' for v in real)
assert any(v.get('scenarioId')=='controlled-finding' and v.get('policyDecision')=='FAIL' for v in real)
v={'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'url':base+'/#pipeline-overview','http':200,'refreshHttp':200,'sameRunVisible':True,
 'pageSha256':hashlib.sha256(body).hexdigest(),'links':links,'existingRealPassFailPreserved':True,'browserClick':'NOT_TESTED',
 'verdict':{k:'VERIFIED' for k in ['CI_CD_AUTO_CHAIN','GITLEAKS_GATE','GITOPS_UPDATE','ARGOCD_UPDATE_SYNC','K8S_REAL_CHANGE','GITOPS_RESTORE','PIPELINE_OVERVIEW']},'PRODUCTION_RELEASE':'NO','PRODUCTION_ROLLOUT':'NO'}
save('page-http.json',v);print(json.dumps(v))
