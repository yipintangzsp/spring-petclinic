"""Bounded observation; only optional refresh metadata on the task-owned demo app."""
import json
import runpy
import sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
stage=sys.argv[1];assert stage in ['baseline','updated','restored']
plan=json.loads((OUT/'prepared.json').read_text());part=plan['commits'][stage]
app=json.loads((OUT/'application-created.json').read_text())
p=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
code=r'''
import json,subprocess,time,datetime
expected=@EXPECTED@;value=@VALUE@;uid=@UID@;stage=@STAGE@
def k(args):return json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=8))
def appread():
 a=k(['-n','argocd','get','application','petclinic-gitops-demo','-o','json'])
 assert a['metadata']['uid']==uid
 s=a['spec'];assert s['source']['repoURL']=='http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git'
 assert s['source']['targetRevision']=='security-demo/gitops-20261105' and s['source']['path']=='infra/devops-lab/gitops-demo'
 assert s['source']['directory']['include']=='configmap.yaml' and not s['source']['directory'].get('recurse',False)
 assert s['destination']['namespace']=='devsecops-test' and not s['syncPolicy']['automated'].get('prune',False)
 for r in a.get('status',{}).get('resources',[]):assert r['kind']=='ConfigMap' and r['name']=='petclinic-gitops-demo' and r.get('namespace')=='devsecops-test'
 return a
a=appread()
# Refresh comparison only; automatic sync remains the existing Argo controller's job.
if stage!='baseline':
 patch=[{'op':'test','path':'/metadata/uid','value':uid}]
 annotations=a['metadata'].get('annotations')
 if annotations is None:patch.append({'op':'add','path':'/metadata/annotations','value':{'argocd.argoproj.io/refresh':'normal'}})
 else:patch.append({'op':'add','path':'/metadata/annotations/argocd.argoproj.io~1refresh','value':'normal'})
 k(['-n','argocd','patch','application','petclinic-gitops-demo','--type=json','-p',json.dumps(patch),'-o','json'])
observations=[]
for i in range(9):
 a=appread();raw=subprocess.check_output(['kubectl','-n','devsecops-test','get','configmap','petclinic-gitops-demo','--ignore-not-found','-o','json'],text=True,timeout=8)
 cm=json.loads(raw) if raw.strip() else None
 s=a.get('status',{});op=s.get('operationState',{})
 actual=cm.get('data',{}).get('demo-stage') if cm else None
 observations.append({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'revision':s.get('sync',{}).get('revision'),'sync':s.get('sync',{}).get('status'),'health':s.get('health',{}).get('status'),'value':actual})
 ok=s.get('sync',{}).get('revision')==expected and s.get('sync',{}).get('status')=='Synced' and s.get('health',{}).get('status')=='Healthy' and actual==value and op.get('phase')=='Succeeded' and op.get('syncResult',{}).get('revision')==expected
 if ok:break
 if i<8:time.sleep(4)
result={'stage':stage,'verified':ok,'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'expectedCommit':expected,'argo':{'revision':s.get('sync',{}).get('revision'),'sync':s.get('sync',{}).get('status'),'health':s.get('health',{}).get('status'),
 'operationPhase':op.get('phase'),'operationRevision':op.get('syncResult',{}).get('revision'),'startedAt':op.get('startedAt'),'finishedAt':op.get('finishedAt'),'managedResources':s.get('resources',[]),'conditions':s.get('conditions',[])},
 'configMap':None if not cm else {'namespace':cm['metadata']['namespace'],'name':cm['metadata']['name'],'uid':cm['metadata']['uid'],'resourceVersion':cm['metadata']['resourceVersion'],
 'data':cm.get('data'),'trackingId':cm['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id'),'labels':cm['metadata'].get('labels',{}),'managers':list({v['manager'] for v in cm['metadata'].get('managedFields',[])})},
 'polls':observations,'configMapDirectWrite':False,'productionMutations':0}
print(json.dumps(result))
'''
for key,v in {'EXPECTED':part['commit'],'VALUE':part['value'],'UID':app['uid'],'STAGE':stage}.items():code=code.replace('@'+key+'@',repr(v))
result=json.loads(p['remote']('sudo -n python3 -',code,58))
name=stage+'.json' if result['verified'] else stage+'-incomplete.json'
with (OUT/name).open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
if not result['verified']:sys.exit(3)
