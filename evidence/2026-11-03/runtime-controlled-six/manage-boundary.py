from pathlib import Path
import json,subprocess,shlex,base64,sys
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-controlled-six';run=json.loads((O/'run.json').read_text())['validationRunId'];name=run+'-scanner'
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def kube(args,obj=None):
 p=subprocess.run(ssh+['sudo -n kubectl '+shlex.join(args)],input=json.dumps(obj).encode() if obj else None,capture_output=True,timeout=45)
 if p.returncode:raise RuntimeError('BOUNDARY_API_FAILED '+args[0]+' '+p.stderr.decode()[-250:])
 return json.loads(p.stdout) if p.stdout.strip() else None
objects=[{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'namespace':'devsecops-execution','name':name},'automountServiceAccountToken':False}]
for ns,rules in [('devsecops-execution',[{'apiGroups':[''],'resources':['pods'],'verbs':['create','get','list','watch','delete']},{'apiGroups':[''],'resources':['pods/exec'],'verbs':['create','get']}]),('data-infra',[{'apiGroups':['coordination.k8s.io'],'resources':['leases'],'resourceNames':['platform-heavy'],'verbs':['get']}])]:
 objects.extend([{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'namespace':ns,'name':name},'rules':rules},{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'namespace':ns,'name':name},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name},'subjects':[{'kind':'ServiceAccount','namespace':'devsecops-execution','name':name}]}])
ledgerFile=O/'boundary-object-ledger.json'
if sys.argv[1]=='prepare':
 assert not ledgerFile.exists();ledger=[]
 before=kube(['-n','devsecops-execution','get','pods','-o','json']);(O/'scanner-before.json').write_text(json.dumps({'objects':[{'name':p['metadata']['name'],'uid':p['metadata']['uid']} for p in before['items']]},indent=2)+'\n')
 assert not before['items'],'TEST_NAMESPACE_BUSY_STOP'
 for o in objects:
  assert kube(['-n',o['metadata']['namespace'],'get',o['kind'],name,'--ignore-not-found','-o','json']) is None
  o['metadata']['labels']={'runtime-validation-run':run};created=kube(['create','-f','-','-o','json'],o);ledger.append({'kind':o['kind'],'namespace':o['metadata']['namespace'],'name':name,'uid':created['metadata']['uid']});ledgerFile.write_text(json.dumps(ledger,indent=2)+'\n')
 token=kube(['-n','devsecops-execution','create','token',name,'--duration=15m','-o','json'])['status']['token']
 ca=kube(['-n','devsecops-execution','get','configmap','kube-root-ca.crt','-o','json'])['data']['ca.crt']
 config={'apiVersion':'v1','kind':'Config','clusters':[{'name':'validation','cluster':{'server':'https://kubernetes.default.svc','certificate-authority-data':base64.b64encode(ca.encode()).decode()}}],'contexts':[{'name':'validation','context':{'cluster':'validation','user':'validation'}}],'current-context':'validation','users':[{'name':'validation','user':{'token':token}}]}
 public={'validationRunId':run,'identity':'system:serviceaccount:devsecops-execution:'+name,'tokenDurationSeconds':900,'noSecretsRead':True}
 script="const fs=require('fs'),x=JSON.parse(fs.readFileSync(0)),p='/tmp/runtime-six-credentials-'+x.run;fs.mkdirSync(p,{mode:448});fs.writeFileSync(p+'/executor.kubeconfig',JSON.stringify(x.config),{mode:384});fs.writeFileSync(p+'/public-binding.json',JSON.stringify(x.public),{mode:384});console.log('BOUNDARY_IDENTITY_STAGED')"
 p=subprocess.run(ssh+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(script)],input=json.dumps({'run':run,'config':config,'public':public}).encode(),capture_output=True,timeout=30);assert p.returncode==0
 (O/'boundary-public-identity.json').write_text(json.dumps(public,indent=2)+'\n');print('BOUNDARY_IDENTITY_STAGED_NO_TOKEN_OUTPUT')
else:
 ledger=json.loads(ledgerFile.read_text())
 pods=kube(['-n','devsecops-execution','get','pods','-o','json']);assert not pods['items'],'SCANNER_POD_REMAINS_STOP'
 for kind in ['RoleBinding','Role','ServiceAccount']:
  for o in [x for x in ledger if x['kind']==kind]:
   actual=kube(['-n',o['namespace'],'get',kind,name,'-o','json']);assert actual['metadata']['uid']==o['uid'] and actual['metadata']['labels']['runtime-validation-run']==run
   # Delete with UID preconditions through raw API, never force or finalizers.
   plural={'ServiceAccount':'serviceaccounts','Role':'roles','RoleBinding':'rolebindings'}[kind];base='/api/v1' if kind=='ServiceAccount' else '/apis/rbac.authorization.k8s.io/v1'
   kube(['delete','--raw',base+'/namespaces/'+o['namespace']+'/'+plural+'/'+name,'-f','-'],{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':o['uid']}})
   assert kube(['-n',o['namespace'],'get',kind,name,'--ignore-not-found','-o','json']) is None
 script="const fs=require('fs'),p='/tmp/runtime-six-credentials-'+process.argv[1];fs.rmSync(p,{recursive:true});console.log(JSON.stringify({privateTokenDirectoryRemoved:!fs.existsSync(p)}))"
 p=subprocess.run(ssh+['sudo -n kubectl exec -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(script)+' '+shlex.quote(run)],capture_output=True,text=True,timeout=30);assert p.returncode==0
 (O/'boundary-cleanup.json').write_text(json.dumps({'rbacObjectsRemoved':len(ledger),'podsRemaining':0,**json.loads(p.stdout)},indent=2)+'\n');print('BOUNDARY_CLEANUP_VERIFIED')
