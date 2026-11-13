import pathlib,json,urllib.request,urllib.error,subprocess,datetime,concurrent.futures
HERE=pathlib.Path(__file__).resolve().parent;op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
def get(p):
 with op.open(base+p,timeout=8)as r:return json.load(r)
runs=get('/api/runs');cfg=get('/api/config');assert not any(r['state']in ['RUNNING','QUEUED']for r in runs['runs'])
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
v=get('/api/overview');s=v['supplyChain'];assert s['harborStatus']=='VERIFIED'and s['signature']['status']=='SIGNATURE_MISSING'and s['sbom']['componentCount']==143 and s['sbom']['candidateDigestBinding']=='UNVERIFIED'and s['releaseApproval']['status']=='NOT_APPROVED'and s['deployment']['status']=='NOT_DEPLOYED'
assert v['dojoReal']['state']=='DELIVERED'and v['ciCd']['build']==6 and v['grafana']['realQuery']=='VERIFIED';assert runs==get('/api/runs')and cfg==get('/api/config')
for path in ['/','/app.js']:
 with op.open(base+path,timeout=8)as r:
  assert r.status==200
  if path=='/app.js':assert b'Supply Chain Security'in r.read()
def check(link):
 try:
  with op.open(link['url'],timeout=5)as r:return {'url':link['url'],'http':r.status,'finalUrl':r.geturl(),'loginRequired':'login'in r.geturl()}
 except urllib.error.HTTPError as e:return {'url':link['url'],'http':e.code,'requiresAuthorizedAccess':e.code in [401,403]}
 except Exception as e:return {'url':link['url'],'http':'UNREACHABLE','errorClass':type(e).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:links=list(pool.map(check,s['links']))
health=json.loads((HERE/'production-health.json').read_text())
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'SUPPLY_CHAIN_VIEW':'VERIFIED','HARBOR_CANDIDATE':'VERIFIED','SBOM_LINK':'INCOMPLETE','COSIGN_CANDIDATE_SIGNATURE':'MISSING','BUILD_PROVENANCE':'VERIFIED','RELEASE_APPROVAL':'NOT_APPROVED','PRODUCTION_RELEASE':'NO','PRODUCTION_ROLLOUT':'NO','pageUrl':base+'/#candidate-overview','pageHttpStatus':200,'overviewApiStatus':200,'sbomComponentCount':143,'sbomScope':'HISTORICAL #270 MAVEN SBOM; candidate digest binding UNVERIFIED','componentRowsDisplayed':len(s['sbom']['components']),'sourceClassification':s['classification'],'signatureVerification':'NOT_EXECUTED_SIGNATURE_MISSING','deployment':'NOT_DEPLOYED','existingRunRecordsAndConfigurationUnchanged':True,'productionHealth':health['health'],'productionConfigurationUnchanged':health['configurationUnchanged'],'links':links,'browserClick':'NOT_TESTED'}
with(HERE/'verdict.json').open('x')as f:json.dump(r,f,indent=2)
print(json.dumps(r))
