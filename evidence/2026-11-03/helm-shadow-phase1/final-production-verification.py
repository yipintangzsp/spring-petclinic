"""Final read-only workload identity verification; no Secret queries or mutation."""
from pathlib import Path
import json,subprocess,shlex,datetime
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def k(args):
 r=subprocess.run(S+['sudo -n kubectl '+shlex.join(args)],capture_output=True,text=True,timeout=25)
 assert r.returncode==0,'Read-only verification failed'
 return json.loads(r.stdout) if r.stdout.strip() else None
rows={}
for name,args in [('deployment-current',['-n','petclinic','get','deployment','petclinic']),('service-current',['-n','petclinic','get','service','petclinic']),('ingress-current',['-n','petclinic','get','ingress','petclinic']),('application-current',['-n','argocd','get','application','petclinic'])]:
 x=k(args+['-o','json']);old=json.loads((O/(name+'.json')).read_text())
 assert x['metadata']['uid']==old['metadata']['uid'] and x['spec']==old['spec'],name
 rows[name]={'uidUnchanged':True,'specUnchanged':True}
 if name=='application-current':
  assert x['status']['sync']['status']=='Synced' and x['status']['health']['status']=='Healthy' and x['status']['sync']['revision']==old['status']['sync']['revision']
  rows[name].update(sync='Synced',health='Healthy',revision=x['status']['sync']['revision'])
 if name=='deployment-current':assert x['status']['readyReplicas']==3
slices=k(['-n','petclinic','get','endpointslices','-l','kubernetes.io/service-name=petclinic','-o','json'])
ready=sum(e.get('conditions',{}).get('ready') is True for x in slices['items'] for e in x.get('endpoints',[]));assert ready==3
app=json.loads((O.parents[2]/'infra/argocd/petclinic-helm-candidate.yaml').read_text());candidate=k(['-n','argocd','get','application',app['metadata']['name'],'--ignore-not-found','-o','json']);assert candidate is None
result={'checkedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'FINAL_READ_ONLY_POST_BUILD_6','objects':rows,'readyEndpoints':ready,'candidateAbsent':True,'productionMutation':0,'release':0,'rollout':0}
(O/'final-production-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
