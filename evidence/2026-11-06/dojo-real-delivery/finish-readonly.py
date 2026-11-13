import ast,pathlib,json,runpy,urllib.request,urllib.error,subprocess,datetime
HERE=pathlib.Path(__file__).resolve().parent
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
tree=ast.parse((HERE.parent/'grafana-v2-real'/'health.py').read_text());code=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='code'for t in n.targets))
health=json.loads(api['remote']('sudo -n python3 -',code,80));prior=json.loads((HERE.parent/'auto-loki-delivery'/'production-health.json').read_text())
health['productionUnchanged']=all(health[k]==prior[k]for k in ['deploymentSpecSha256','argoSpecSha256','argoRevision','generation','pods','socketMode'])
health['health']='HEALTHY'if health['ready']==3 and health['http']==200 and health['argoHealth']=='Healthy'and health['argoSync']=='Synced'and all(n['ready']=='True'for n in health['nodes'])else'DEGRADED'
with(HERE/'production-health.json').open('x')as f:json.dump(health,f,indent=2)
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
def get(path):
 with op.open(base+path,timeout=8)as r:return json.load(r)
runs=get('/api/runs');assert not any(r['state']in ['RUNNING','QUEUED']for r in runs['runs'])
cfg=get('/api/config')
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
v=get('/api/overview');assert v['dojoReal']['state']=='BLOCKED'and v['dojoReal']['findingCount']==2 and v['dojoReal']['queryState']=='NOT_TESTED'
assert cfg==get('/api/config')and runs==get('/api/runs')
with op.open(base+'/',timeout=8)as r:assert r.status==200
with op.open(base+'/app.js',timeout=8)as r:assert 'DefectDojo · 真实漏洞治理'.encode()in r.read()
try:
 with op.open('http://defectdojo.devops.local/login',timeout=10)as r:dojo={'http':r.status,'finalUrl':r.geturl()}
except urllib.error.HTTPError as e:dojo={'http':e.code}
except (urllib.error.URLError,TimeoutError):dojo={'http':'UNREACHABLE'}
res={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'DEFECTDOJO_REAL_WRITE':'INCOMPLETE','DEFECTDOJO_QUERY_BACK':'INCOMPLETE','SEMGREP_FINDING_MAPPING':'VERIFIED','DEFECTDOJO_DEDUP':'NOT_TESTED','SECURITY_MANAGER_DOJO_LINK':'INCOMPLETE','pageStatus':'BLOCKED','pageUrl':base+'/#candidate-overview','pageHttpStatus':200,'dojoService':dojo,'sourceRunId':v['dojoReal']['runId'],'mappedFindings':2,'newScans':0,'credentialValuesRead':0,'governanceWrites':0,'productionGovernanceMutations':0,'productionHealth':health['health'],'productionUnchanged':health['productionUnchanged'],'configurationUnchanged':True,'existingRunRecordsUnchanged':True,'productionSecurityManager':'NOT_ACTIVE','release':0,'rollout':0,'blocker':'DEDICATED_NONADMIN_WRITER_AND_NONPRODUCTION_CONTEXT_NOT_AUTHORIZED','authorizationPlan':'CHANGE-PLAN.md'}
with(HERE/'verdict.json').open('x')as f:json.dump(res,f,indent=2)
print(json.dumps(res))
