import pathlib,json,subprocess,urllib.request,urllib.error,hashlib,datetime
here=pathlib.Path(__file__).resolve().parent;a=json.loads((here/'acceptance.json').read_text());base='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(p,h={}):
 with op.open(urllib.request.Request(base+p,headers=h),timeout=12)as r:return r.status,r.read()
def js(p,h={}):return json.loads(get(p,h)[1])
p=js('/api/sbom/session')['projects'][0];h={'X-Project-Token':p['projectToken']};before=js('/api/runs/'+a['runId'],h);assert not any(r['state']in ['RUNNING','QUEUED']for r in js('/api/runs',h)['runs'])
r=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert r.returncode==0,r.stderr
p=js('/api/sbom/session')['projects'][0];h={'X-Project-Token':p['projectToken']};after=js('/api/runs/'+a['runId'],h);assert before==after and after['evidenceClass']=='REAL'and after['state']=='COMPLETED'
status,raw=get(a['downloadApi'],h);assert status==200 and hashlib.sha256(raw).hexdigest()==a['sbomSha256']
assert get('/')[0]==200;script=get('/app.js')[1].decode();assert '读取原始 SBOM / 展开组件'in script and 'new Blob([raw]'in script and 'Result Router'in script
cfg=js('/api/config');assert cfg['settings']['enabled']and cfg['settings']['securityLevel']=='standard'and all(x['enabled']for x in cfg['settings']['plugins'].values())
old=[]
for p in pathlib.Path('.devsecops/security-view-runs-v1').glob('web-*/result.json'):
 x=json.loads(p.read_text())
 if x.get('pluginId')in ['gitleaks','semgrep','cosign']and x.get('evidenceClass')=='REAL'and x.get('state')=='COMPLETED':old.append(x)
previous={plugin:sorted({x['policyDecision']for x in old if x['pluginId']==plugin})for plugin in ['gitleaks','semgrep','cosign']}
assert all(v==['FAIL','PASS']for v in previous.values())
for plugin in previous:
 for decision in ['PASS','FAIL']:
  x=next(x for x in old if x['pluginId']==plugin and x['policyDecision']==decision);assert js('/api/runs/'+x['runId'])['resultDigest']==x['resultDigest']
for path,head in [(a['downloadApi'],{}),(a['downloadApi'],{'X-Project-Token':'other-project-token'}),(a['downloadApi'].replace('/java-sbom-demo/','/other-project/'),h),('/api/plugins',{'Host':'untrusted.devops.local'}),('/api/sbom/session',{'Origin':'http://untrusted.example'})]:
 try:get(path,head);raise AssertionError('UNAUTHORIZED_ACCESS')
 except urllib.error.HTTPError as e:assert e.code==403
x={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'url':base+'/#candidate-overview','httpStatus':200,'runId':a['runId'],'recordAfterRestartIdentical':True,'rawDownloadSha256':hashlib.sha256(raw).hexdigest(),'componentCount':len(json.loads(raw)['components']),'uiAssetServed':True,'projectHostOriginDenials':5,'fixedProjectBoundaryVerified':True,'multiTenantRbac':'NOT_IMPLEMENTED_LOCAL_OPERATOR_ONLY','threePluginHistory':previous,'configuration':cfg['settings'],'lokiSameRunQueried':after['lokiDelivery']['queryState'],'browserClick':'NOT_TESTED','newGenerationsDuringVerification':0,'harborCandidateSbomLink':'UNVERIFIED','cosignCandidateSignature':'MISSING','release':0,'rollout':0}
with(here/'web-persistence.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
