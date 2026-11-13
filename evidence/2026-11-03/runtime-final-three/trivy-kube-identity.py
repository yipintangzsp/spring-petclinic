from pathlib import Path
import json,subprocess,shlex,base64,sys
O=Path('evidence/2026-11-03/runtime-final-three');run=json.load(open(O/'run.json'))['validationRunId'];ns=run+'-trivy';name='maps-reader';role=run+'-maps'
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def k(a,o=None):
 p=subprocess.run(SSH+['sudo -n kubectl '+shlex.join(a)],input=json.dumps(o).encode() if o is not None else None,capture_output=True,timeout=35)
 if p.returncode:raise RuntimeError('TRIVY_IDENTITY_API_FAILED '+a[0]+' '+p.stderr.decode()[-300:])
 return json.loads(p.stdout) if p.stdout.strip() else None
def save(n,x):(O/n).write_text(json.dumps(x,indent=2)+'\n')
ledger=[]
def create(o):
 m=o['metadata'];m['labels']={'runtime-validation-run':run};assert k((['-n',m['namespace']] if m.get('namespace') else [])+['get',o['kind'],m['name'],'--ignore-not-found','-o','json']) is None
 v=k(['create','-f','-','-o','json'],o);ledger.append({'kind':o['kind'],'name':m['name'],'namespace':m.get('namespace'),'uid':v['metadata']['uid'],'apiVersion':v['apiVersion']});save('trivy-kube-ledger.json',ledger)
if sys.argv[1]=='prepare':
 assert not (O/'trivy-kube-ledger.json').exists();d=k(['-n','petclinic','get','deployment','petclinic','-o','json']);selector=','.join(a+'='+b for a,b in d['spec']['selector']['matchLabels'].items());pods=k(['-n','petclinic','get','pods','-l',selector,'-o','json'])['items'];targets=[{'name':p['metadata']['name'],'uid':p['metadata']['uid']} for p in pods if any(c.get('ready') and c['name']=='petclinic' for c in p['status'].get('containerStatuses',[]))];assert targets
 create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}});create({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'namespace':ns,'name':name},'automountServiceAccountToken':False})
 rules=[{'apiGroups':['apps'],'resources':['deployments'],'resourceNames':['petclinic'],'verbs':['get']},{'apiGroups':[''],'resources':['pods'],'verbs':['list']},{'apiGroups':[''],'resources':['pods'],'resourceNames':[t['name'] for t in targets],'verbs':['get']},{'apiGroups':[''],'resources':['pods/exec'],'resourceNames':[t['name'] for t in targets],'verbs':['create','get']}]
 create({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'namespace':'petclinic','name':role},'rules':rules});create({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'namespace':'petclinic','name':role},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':role},'subjects':[{'kind':'ServiceAccount','namespace':ns,'name':name}]})
 token=k(['-n',ns,'create','token',name,'--duration=20m','-o','json'])['status']['token'];ca=k(['-n',ns,'get','configmap','kube-root-ca.crt','-o','json'])['data']['ca.crt'];cfg={'apiVersion':'v1','kind':'Config','clusters':[{'name':'v','cluster':{'server':'https://kubernetes.default.svc','certificate-authority-data':base64.b64encode(ca.encode()).decode()}}],'users':[{'name':'v','user':{'token':token}}],'contexts':[{'name':'v','context':{'cluster':'v','user':'v'}}],'current-context':'v'}
 public={'validationRunId':run,'selector':selector,'pods':targets,'identity':'system:serviceaccount:'+ns+':'+name,'allowedExec':['cat','/proc/1/maps'],'productionCredentialReadsAllowed':False}
 node="const fs=require('fs'),x=JSON.parse(fs.readFileSync(0)),p='/tmp/runtime-three-'+x.public.validationRunId;if(!fs.existsSync(p))throw Error('No prepared robot boundary');fs.writeFileSync(p+'/trivy-kubeconfig',JSON.stringify(x.cfg),{mode:384});fs.writeFileSync(p+'/trivy-kube-public.json',JSON.stringify(x.public),{mode:384});console.log('READ_MAPS_MIN_RBAC_STAGED');"
 p=subprocess.run(SSH+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(node)],input=json.dumps({'cfg':cfg,'public':public}).encode(),capture_output=True,timeout=25);assert p.returncode==0;save('trivy-kube-public.json',public);print('TRIVY_READ_ONLY_MAPS_IDENTITY_READY')
else:
 ledger=json.load(open(O/'trivy-kube-ledger.json'));removed=[]
 for kind in ['RoleBinding','Role','ServiceAccount','Namespace']:
  for o in [x for x in ledger if x['kind']==kind]:
   args=(['-n',o['namespace']] if o['namespace'] else []);v=k(args+['get',kind,o['name'],'-o','json']);assert v['metadata']['uid']==o['uid'] and v['metadata']['labels']['runtime-validation-run']==run
   group='/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'];plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Role':'roles','RoleBinding':'rolebindings'}[kind];path=group+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural+'/'+o['name'];k(['delete','--raw',path,'-f','-'],{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':o['uid']}})
   for _ in range(80):
    if k(args+['get',kind,o['name'],'--ignore-not-found','-o','json']) is None:break
    __import__('time').sleep(.25)
   else:raise RuntimeError('TRIVY_RBAC_DELETE_NOT_PROVEN')
   removed.append(o)
 node="const fs=require('fs'),p='/tmp/runtime-three-'+process.argv[1];for(const n of ['trivy-kubeconfig','trivy-kube-public.json','trivy-boundary.json'])fs.rmSync(p+'/'+n,{force:true});console.log(JSON.stringify({tokenRemoved:!fs.existsSync(p+'/trivy-kubeconfig'),remainingNames:fs.existsSync(p)?fs.readdirSync(p):[]}));"
 p=subprocess.run(SSH+['sudo -n kubectl exec -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(node)+' '+shlex.quote(run)],capture_output=True,text=True,timeout=25);assert p.returncode==0;save('trivy-kube-cleanup.json',{'removed':removed,**json.loads(p.stdout)});print('TRIVY_MAPS_IDENTITY_REMOVED')
