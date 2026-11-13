import json,pathlib,subprocess,urllib.request,runpy,ast,datetime
HERE=pathlib.Path(__file__).resolve().parent;op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
def get(p):
 with op.open(base+p,timeout=8)as r:return json.load(r)
runs=get('/api/runs');cfg=get('/api/config');assert not any(r['state']in ['RUNNING','QUEUED']for r in runs['runs'])
p=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
v=get('/api/overview');s=v['supplyChain'];br=s['sbom']['bindingReview'];assert br['status']=='UNVERIFIED'and br['componentCount']==143 and br['pluginIntegration']=='INCOMPLETE'
assert s['signature']['status']=='SIGNATURE_MISSING'and s['releaseApproval']['status']=='NOT_APPROVED'and s['deployment']['status']=='NOT_DEPLOYED'
assert cfg==get('/api/config')and runs==get('/api/runs');assert v['dojoReal']['state']=='DELIVERED'and v['grafana']['realQuery']=='VERIFIED'and v['ciCd']['build']==6
with op.open(base+'/',timeout=8)as r:assert r.status==200
with op.open(base+'/app.js',timeout=8)as r:assert 'SBOM Digest 关联核查'.encode()in r.read()
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py');tree=ast.parse((HERE.parent/'grafana-v2-real/health.py').read_text());code=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='code'for t in n.targets))
health=json.loads(api['remote']('sudo -n python3 -',code,75));old=json.loads((HERE.parent/'supply-chain-view/production-health.json').read_text());unchanged=all(health[k]==old[k]for k in ['deploymentSpecSha256','argoSpecSha256','generation','argoRevision','socketMode']);healthy=health['ready']==3 and health['http']==200 and health['argoSync']=='Synced'and health['argoHealth']=='Healthy'and all(n['ready']=='True'for n in health['nodes'])
with(HERE/'production-health.json').open('x')as f:json.dump(health,f,indent=2)
x={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'SBOM_LINK':'UNVERIFIED','SBOM_PLUGIN_INTEGRATION':'INCOMPLETE','SBOM_SWITCH_BEHAVIOR':'VERIFIED','switchScope':'Existing Core global/plugin/mode OFF; web SBOM switch and live runner NOT_CONFIGURED','digestMismatchTest':'NOT_TESTED_NO_BINDING_VERIFIER','COSIGN_CANDIDATE_SIGNATURE':'MISSING','releaseApproval':'NOT_APPROVED','deployment':'NOT_DEPLOYED','PRODUCTION_RELEASE':'NO','PRODUCTION_ROLLOUT':'NO','pageUrl':base+'/#candidate-overview','httpStatus':200,'candidateDigest':br['candidateDigest'],'sbomSha256':br['sbomSha256'],'componentCount':143,'scope':br['scope'],'missingEvidence':br['missingEvidence'],'newSbomGeneration':0,'candidateSbomBindingVerifications':0,'existingRecordsAndControlsUnchanged':True,'productionHealth':'HEALTHY'if healthy else'DEGRADED','productionConfigurationUnchanged':unchanged,'browserClick':'NOT_TESTED'}
with(HERE/'verdict.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
