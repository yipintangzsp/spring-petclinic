import pathlib,json,urllib.request,urllib.error,subprocess,time,hashlib
here=pathlib.Path(__file__).resolve().parent;base='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}));creds=json.loads(pathlib.Path('.devsecops/security-view-project-access-v1.json').read_text());admin={'Authorization':'Bearer '+creds['operatorToken']};A='java-sbom-demo';B=A+'-b';ha={'X-Project-Token':creds['projects'][A]};hb={'X-Project-Token':creds['projects'][B]}
def req(p,h={},v=None):
 if v is not None:h={**h,'Content-Type':'application/json','Origin':base,'X-CSRF-Token':get('/api/plugins')['csrfToken']}
 with op.open(urllib.request.Request(base+p,headers=h,data=json.dumps(v).encode()if v is not None else None),timeout=10)as r:return r.status,r.read(),r.headers
def get(p,h={}):return json.loads(req(p,h)[1])
def post(p,v,h):return json.loads(req(p,h,v)[1])
def deny(p,h={},v=None):
 try:req(p,h,v);raise AssertionError('UNAUTHORIZED')
 except urllib.error.HTTPError as e:assert e.code==403,(p,e.code)
def disabled(project,h):
 r=post('/api/run',{'pluginId':'sbom','scenarioId':'clean','projectId':project},h)
 for _ in range(40):
  r=get('/api/runs/'+r['runId'],h)
  if r['state']not in ['QUEUED','RUNNING']:break
  time.sleep(.1)
 assert r['state']=='DISABLED'and r['scannerExecuted']==False and r['evaluationCount']==0
 assert not(pathlib.Path('.devsecops/security-view-runs-v1')/r['runId']/'artifact').exists()
 return r['runId']
original=get('/api/config',admin);pa=get('/api/projects/'+A+'/config',ha);originalA=get('/api/runs/web-6dbc4f41-3d82-4a6c-8b1c-b12f928c4f25',ha)
assert len(get('/api/sbom/session',ha)['projects'])==1 and get('/api/sbom/session',ha)['projects'][0]['projectId']==A
deny('/api/sbom/session');deny('/api/config',ha);deny('/api/projects/'+B+'/config',ha);deny('/api/projects/'+B+'/config',ha,{'revision':original['revision'],'sbomEnabled':False});deny('/api/sbom/operator-ticket',ha,{})
deniedBefore=len(list(pathlib.Path('.devsecops/security-view-runs-v1').iterdir()));deny('/api/run',ha,{'pluginId':'sbom','scenarioId':'clean','projectId':'unknown-project'});assert deniedBefore==len(list(pathlib.Path('.devsecops/security-view-runs-v1').iterdir()))
b=post('/api/projects/'+B+'/config',{'revision':original['revision'],'sbomEnabled':False},hb);assert get('/api/projects/'+A+'/config',ha)['effectiveEnabled']and not b['effectiveEnabled'];r1=disabled(B,hb)
c=get('/api/config',admin);s=c['settings'];s['plugins']['sbom']['enabled']=False;post('/api/config',{'revision':c['revision'],'settings':s},admin)
assert not get('/api/projects/'+A+'/config',ha)['effectiveEnabled']and not get('/api/projects/'+B+'/config',hb)['effectiveEnabled'];r2=disabled(A,ha);r3=disabled(B,hb)
c=get('/api/config',admin);post('/api/config',{'revision':c['revision'],'settings':original['settings']},admin)
subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],check=True,capture_output=True,timeout=20)
assert not get('/api/projects/'+B+'/config',hb)['sbomEnabled']and get('/api/projects/'+A+'/config',ha)['effectiveEnabled']
b=get('/api/projects/'+B+'/config',hb);post('/api/projects/'+B+'/config',{'revision':b['revision'],'sbomEnabled':True},hb)
assert get('/api/projects/'+A+'/config',ha)['effectiveConfig']['effectiveConfigDigest']==pa['effectiveConfig']['effectiveConfigDigest']
assert get('/api/runs/'+originalA['runId'],ha)==originalA
ticket=post('/api/sbom/operator-ticket',{},admin)['ticket']
# Do not follow the redirect; cookie proves operator login without exposing secrets.
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
login=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
try:login.open(base+'/operator-login?ticket='+ticket);raise AssertionError('EXPECTED_REDIRECT')
except urllib.error.HTTPError as e:assert e.code==303;cookie=e.headers['Set-Cookie'].split(';')[0]
assert len(get('/api/sbom/session',{'Cookie':cookie})['projects'])==2;deny('/operator-login?ticket='+ticket)
x={'projects':[A,B],'projectBDisabledStopsRunner':True,'projectAEffectiveConfigUnchanged':True,'globalSbomOffBlocksBoth':True,'restartPersistence':True,'projectCredentialsCannotMintOtherProjectOrOperator':True,'unauthorizedProjectRejectedBeforeRunCreation':True,'operatorLoginCookieVerified':True,'oneTimeTicketReplayDenied':True,'projectAHistoricalRecordUnchanged':True,'disabledRunIds':[r1,r2,r3],'bothProjectDefaultsEnabled':True}
with(here/'controls-and-access.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
