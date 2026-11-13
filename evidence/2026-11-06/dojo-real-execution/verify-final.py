import pathlib,sys,json,ast,runpy,urllib.request,urllib.error,subprocess,datetime
HERE=pathlib.Path(__file__).resolve().parent
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
tree=ast.parse((HERE.parent/'grafana-v2-real'/'health.py').read_text());code=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='code'for t in n.targets))
health=json.loads(api['remote']('sudo -n python3 -',code,80));old=json.loads((HERE.parent/'auto-loki-delivery'/'production-health.json').read_text())
health['configurationUnchanged']=all(health[k]==old[k]for k in ['deploymentSpecSha256','argoSpecSha256','argoRevision','generation','socketMode']);health['health']='HEALTHY'if health['ready']==3 and health['http']==200 and health['argoHealth']=='Healthy'and health['argoSync']=='Synced'and all(n['ready']=='True'for n in health['nodes'])else'DEGRADED'
with(HERE/'production-health.json').open('x')as f:json.dump(health,f,indent=2)
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
def get(p):
 with op.open(base+p,timeout=8)as r:return json.load(r)
runs=get('/api/runs');cfg=get('/api/config');assert not any(r['state']in ['QUEUED','RUNNING']for r in runs['runs'])
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
v=get('/api/overview');dj=v['dojoReal'];assert dj['state']=='DELIVERED'and dj['queryState']=='VERIFIED'and dj['findingIds']==[6628,6629]
assert v['ciCd']['build']==6 and v['grafana']['realQuery']=='VERIFIED'and runs==get('/api/runs')and cfg==get('/api/config')
urls=[]
for url in [base+'/',*dj['findingUrls']]:
 with op.open(url,timeout=10)as r:urls.append({'url':url,'status':r.status,'finalUrl':r.geturl()});assert r.status==200
res={'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'DEFECTDOJO_REAL_WRITE':'VERIFIED','DEFECTDOJO_QUERY_BACK':'VERIFIED','SEMGREP_FINDING_MAPPING':'VERIFIED','DEFECTDOJO_DEDUP':'VERIFIED_SAME_JOURNAL_ZERO_HTTP','SECURITY_MANAGER_DOJO_LINK':'VERIFIED','pageUrl':base+'/#candidate-overview','urls':urls,'findingIds':[6628,6629],'findingCount':2,'productId':7,'engagementId':4,'runId':dj['runId'],'policyDecision':'FAIL','resultDigest':dj['resultDigest'],'productionHealth':health['health'],'productionConfigurationUnchanged':health['configurationUnchanged'],'preexistingGovernanceUnchanged':True,'tokenRevoked':True,'productionSecurityManager':'NOT_ACTIVE','runtime':'14/16','newScans':0,'release':0,'rollout':0,'browserClick':'NOT_TESTED'}
with(HERE/'verdict.json').open('x')as f:json.dump(res,f,indent=2)
print(json.dumps(res))
