import pathlib,runpy,json,ast,sys
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;a=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
s=pathlib.Path('evidence/2026-11-06/grafana-v2-real/health.py').read_text();code=next(n.value.value for n in ast.parse(s).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='code'for t in n.targets))
code=code.replace('print(json.dumps({','x={').replace("'rollout':0}))","'rollout':0}")
code+=r'''
import pathlib
roots=['/var/tmp/security-manager-gitleaks-realcommit-20261107','/var/tmp/security-manager-gitleaks-recovery-20261107','/var/tmp/security-manager-gitleaks-final-20261107','/var/tmp/security-manager-gitleaks-timeout60-20261107']
clean={}
for root in roots:
 r=pathlib.Path(root);out=r/'outputs'
 clean[root]={'readTokenAbsent':not(r/'read-token').exists(),'askpassAbsent':not(r/'askpass.py').exists(),'sourceOrPrivateScanDirs':[]if not out.is_dir()else[p.name for p in out.iterdir()if p.is_dir()and p.name.startswith(('source-web-','scan-','read-preflight-','input-check-','blob-inspect-'))]}
x['taskCleanup']=clean;x['ciSocketDirectoryAbsent']=not pathlib.Path('/var/lib/security-gitleaks/ci-channel').exists();x['ciCapabilityAbsent']=not pathlib.Path('/var/lib/security-gitleaks/manager-ci-capability.json').exists();x['pushTokenAbsent']=not pathlib.Path('/var/lib/security-gitops-demo/realcommit-push-token').exists();x['sourceEntryHasNoTemporaryDispatch']=b'commit-v1'not in pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py').read_bytes()
print(json.dumps(x))
'''
x=json.loads(a['remote']('sudo -n python3 -',code,90));x['jenkins']=a['jenkins']();old=json.loads(pathlib.Path('evidence/2026-11-07/timeout60/production-final.json').read_text());x['productionUnchanged']=x['deploymentSpecSha256']==old['deploymentSpecSha256']and x['argoSpecSha256']==old['argoSpecSha256']and x['jenkins']['summarySha256']==old['jenkins']['summarySha256']and x['jenkins']['jobDefinitionSha256']==old['jenkins']['jobDefinitionSha256'];x['health']='HEALTHY'if x['ready']==3 and x['http']==200 and x['argoSync']=='Synced'and x['argoHealth']=='Healthy'and all(n['ready']=='True'for n in x['nodes'])else'DEGRADED'
with(h/'server-check.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
