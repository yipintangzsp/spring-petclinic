import pathlib,json,urllib.request,urllib.error,time,hashlib,subprocess
h=pathlib.Path(__file__).resolve().parent;b='http://security.devops.local:17862';o=urllib.request.build_opener(urllib.request.ProxyHandler({}));c=json.loads(pathlib.Path('.devsecops/security-view-project-access-v1.json').read_text());A='java-sbom-demo';B=A+'-b';ha={'X-Project-Token':c['projects'][A]};hb={'X-Project-Token':c['projects'][B]}
def raw(p,head):
 with o.open(urllib.request.Request(b+p,headers=head),timeout=10)as r:return r.read()
def get(p,head):return json.loads(raw(p,head))
for _ in range(100):
 rs=get('/api/runs',hb)['runs'];r=next((r for r in rs if r['projectId']==B and r['state']!='DISABLED'),None)
 if r and r['state']not in ['QUEUED','RUNNING']:break
 time.sleep(.5)
with(h/'real-result.json').open('x')as f:json.dump(r,f,indent=2)
print(json.dumps({k:r.get(k)for k in ['runId','state','policyDecision','scannerExitCode','evaluationCount','componentCount','sbomSha256','resultDigest','lokiDelivery']}),flush=True)
assert r['state']=='COMPLETED'and r['evidenceClass']=='REAL'and r['evaluationCount']==1 and r['policyDecision']=='PASS'
ra=get('/api/runs/web-6dbc4f41-3d82-4a6c-8b1c-b12f928c4f25',ha);pa='/api/projects/'+A+'/runs/'+ra['runId']+'/sbom';pb='/api/projects/'+B+'/runs/'+r['runId']+'/sbom';ba=raw(pa,ha);bb=raw(pb,hb)
assert hashlib.sha256(ba).hexdigest()==ra['sbomSha256']and hashlib.sha256(bb).hexdigest()==r['sbomSha256']and ba!=bb
assert r['sourceArtifactSha256']!=ra['sourceArtifactSha256']
for p,head in [(pb,ha),(pa,hb),('/api/runs/'+r['runId'],ha),('/api/runs/'+ra['runId'],hb),(pb.replace('/'+B+'/','/'+A+'/'),ha)]:
 try:raw(p,head);raise AssertionError('CROSS_PROJECT_LEAK')
 except urllib.error.HTTPError as e:assert e.code==403
assert all(v['projectId']==A for v in get('/api/runs',ha)['runs'])and all(v['projectId']==B for v in get('/api/runs',hb)['runs'])
assert r['lokiDelivery']['queryState']=='VERIFIED'and r['lokiDelivery']['state']=='DELIVERED'
subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],check=True,capture_output=True,timeout=20)
assert get('/api/runs/'+r['runId'],hb)==r and raw(pb,hb)==bb and get('/api/runs/'+ra['runId'],ha)==ra
with(h/'generated-b.cdx.json').open('xb')as f:f.write(bb)
x={'projects':{A:{'runId':ra['runId'],'sha256':ra['sbomSha256'],'components':ra['componentCount'],'inputSha256':ra['sourceArtifactSha256'],'source':'HISTORICAL_UNCHANGED'},B:{'runId':r['runId'],'sha256':r['sbomSha256'],'components':r['componentCount'],'inputSha256':r['sourceArtifactSha256'],'source':'REAL_BROWSER_EXECUTION'}},'policy':r['policyDecision'],'evaluationCount':1,'router':r['router'],'loki':r['lokiDelivery'],'projectArtifactCrossReadDenials':5,'restartPersistence':True,'browserClick':'VERIFIED','release':0,'rollout':0}
with(h/'acceptance.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
