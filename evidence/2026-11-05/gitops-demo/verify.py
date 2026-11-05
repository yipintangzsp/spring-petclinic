"""Small HTTP acceptance; no writes to remote systems or scan requests."""
import concurrent.futures
import datetime
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
op = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
base = 'http://security.devops.local:17862'
def get(url):
    try:
        with op.open(url, timeout=5) as r:
            return r.status, r.read(2*1024*1024)
    except urllib.error.HTTPError as e:
        return e.code, b''

status, raw = get(base+'/')
assert status == 200
card = raw.decode().split('<!-- GITOPS_DEMO_RESULT_BEGIN -->')[1].split('<!-- GITOPS_DEMO_RESULT_END -->')[0]
state = json.loads((OUT/'observation.json').read_text())
for value in ['REAL CHANGE · INCOMPLETE', 'HISTORICAL', 'NOT_EXECUTED',
              state['production']['argo']['revision'], '只读排障命令', '恢复']:
    assert value in card
assert get(base+'/')[1] == raw
urls = re.findall('href="(http://[^\"]+)"',card)
assert len(urls) == 5
def navigation(url):
    code,_ = get(url)
    assert code in [200,301,302,303,307,308,401,403], (url,code)
    return {'url':url,'http':code,'authenticatedContent':'NOT_TESTED'}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    nav = list(executor.map(navigation,urls))
status, data = get(base+'/api/runs')
assert status == 200
runs = json.loads(data)['runs']
real = [r for r in runs if r.get('pluginId')=='gitleaks' and r.get('evidenceClass')=='REAL' and r.get('state')=='COMPLETED']
assert any(r.get('scenarioId')=='clean' and r.get('policyDecision')=='PASS' for r in real)
assert any(r.get('scenarioId')=='controlled-finding' and r.get('policyDecision')=='FAIL' for r in real)
previous = json.loads((OUT.parent/'candidate-dry-run-isolation/health.json').read_text())
prod = state['production']
unchanged = prod['specSha256']==previous['specSha256'] and prod['generation']==previous['generation'] and prod['image']==previous['image']
assert unchanged
assert prod['ready']==prod['desired']==3 and prod['http']==200 and prod['readyEndpoints']==3
receipt = {'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'pageUrl':base+'/#pipeline-overview','pageHttp':200,'refreshHttp':200,'navigation':nav,
 'existingRealPassFailPreserved':True,'browserClick':'NOT_TESTED',
 'GITOPS_DEMO_REAL_CHANGE':'INCOMPLETE','ARGOCD_SYNC':'VERIFIED',
 'KUBERNETES_STATE_CHANGE':'INCOMPLETE','GITOPS_RESTORE':'INCOMPLETE',
 'PIPELINE_OVERVIEW':'VERIFIED','PRODUCTION_PETCLINIC_UNCHANGED':'YES',
 'productionObservedAt':state['observedAt'],'productionState':{'ready':3,'http':200,'argo':prod['argo']['sync']+'/'+prod['argo']['health']},
 'newGitOpsCommit':None,'restoreCommit':None,'gitopsRevision':prod['argo']['revision'],
 'newApplicationCount':0,'pushCount':0,'releaseCount':0,'rolloutCount':0}
with (OUT/'acceptance.json').open('x') as f:
    json.dump(receipt,f,indent=2,ensure_ascii=False)
print(json.dumps(receipt,ensure_ascii=False))
