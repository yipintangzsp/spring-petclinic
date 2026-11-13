import pathlib,json,urllib.request,urllib.error,http.client,socket,hashlib
from runpy import run_path
h=pathlib.Path(__file__).resolve().parent;x=json.loads((h/'build8-observed.json').read_text());assert x['result']=='SUCCESS'and x['causes']==['com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause'];m=x['manager'];assert m['state']=='COMPLETED'and m['evaluationCount']==1 and m['policyDecision']=='PASS'and m['scannerExitCode']==0
base='http://security.devops.local:17862';o=urllib.request.build_opener(urllib.request.ProxyHandler({}));cred=json.loads(pathlib.Path('.devsecops/security-view-project-access-v1.json').read_text());admin={'Authorization':'Bearer '+cred['operatorToken']}
def get(p,h):
 with o.open(urllib.request.Request(base+p,headers=h),timeout=10)as r:return json.load(r)
r=get('/api/runs/'+m['runId'],admin);assert all(r[k]==m[k]for k in ['resultDigest','artifactDigest','ciContext','projectId','policyDecision']);assert r['scannerExecuted']and r['findingsCount']==0
for hdr in [{},{'X-Project-Token':cred['projects']['java-sbom-demo']},{'X-Project-Token':cred['projects']['java-sbom-demo-b']}]:
 try:get('/api/runs/'+r['runId'],hdr);raise AssertionError('CI_RESULT_LEAK')
 except urllib.error.HTTPError as e:assert e.code==403
cap=json.loads(pathlib.Path('.devsecops/security-view-ci-capability-v1.json').read_text())
class UNIX(http.client.HTTPConnection):
 def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(5);self.sock.connect(cap['stateDirectory']+'/ci.sock')
def ci(method,path,v=None,auth=None):
 c=UNIX('localhost');c.request(method,path,body=None if v is None else json.dumps(v),headers={'Content-Type':'application/json','Authorization':'Bearer '+(auth or cap['token'])});q=c.getresponse();return q.status,json.loads(q.read())
v={k:r['ciContext'][k]for k in ['projectId','sourceRepository','commitSha','ciProvider','jobId','buildId','trigger','pluginId','scenarioId']}
status,response=ci('POST','/v1/runs',v);assert status==409 and response['error']=='CI_ONE_RUN_BUDGET_USED'
assert ci('GET','/v1/runs/'+r['runId'],auth='wrong-token')[0]==403
assert ci('GET','/v1/runs/web-6dbc4f41-3d82-4a6c-8b1c-b12f928c4f25')[0]==403
assert ci('GET','/api/config')[0]==404
A='web-6dbc4f41-3d82-4a6c-8b1c-b12f928c4f25';B='web-b52dbc8e-b584-4c0d-ad53-1c01ce116ddf';old= json.loads(pathlib.Path('evidence/2026-11-06/sbom-second-project/acceptance.json').read_text())['projects']
for project,id in [('java-sbom-demo',A),('java-sbom-demo-b',B)]:
 got=get('/api/runs/'+id,{'X-Project-Token':cred['projects'][project]});assert got['sbomSha256']==old[project]['sha256']
with(h/'real-run.json').open('x')as f:json.dump(r,f,indent=2)
with(h/'acceptance.json').open('x')as f:json.dump({'runId':r['runId'],'projectId':r['projectId'],'commitSha':v['commitSha'],'buildId':8,'buildUrl':x['url'],'policy':'PASS','evaluationCount':1,'resultDigest':r['resultDigest'],'scannerExitCode':0,'lokiQuery':r['lokiDelivery']['queryState'],'runReplayRejected':True,'wrongIdentityRejected':True,'otherRunRejected':True,'browserRoutesNotExposed':True,'anonymousAndSbomCredentialsDenied':True,'sbomABUnchanged':True,'sourceScope':r['ciContext']['sourceScope'],'actualPushes':1,'eventIds':[342,343],'initialFailureBuild':7,'successfulBuild':8,'release':0,'rollout':0},f,indent=2)
print(json.dumps({'runId':r['runId'],'projectId':r['projectId'],'resultDigest':r['resultDigest'],'ciAuthorization':'VERIFIED','oneRunBudget':'VERIFIED','sbomABUnchanged':True}))
