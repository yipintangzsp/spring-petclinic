from pathlib import Path
import json,subprocess,shlex,base64,sys,time
O=Path('evidence/2026-11-03/runtime-final-three');run=json.load(open(O/'run.json'))['validationRunId'];ns=run+'-cosign';name='signature-executor';label={'runtime-validation-run':run};secret=run+'-registry';SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def k(a,o=None):
 p=subprocess.run(SSH+['sudo -n kubectl '+shlex.join(a)],input=json.dumps(o).encode() if o is not None else None,capture_output=True,timeout=45)
 if p.returncode:raise RuntimeError('COSIGN_KUBE_API_FAILED '+a[0]+': '+p.stderr.decode()[-450:])
 return json.loads(p.stdout) if p.stdout.strip() else None
def node(code,input=None):
 p=subprocess.run(SSH+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(code)],input=json.dumps(input).encode() if input is not None else None,capture_output=True,timeout=30);assert p.returncode==0,'PRIVATE_TEST_TRANSFER_FAILED';return json.loads(p.stdout)
def save(n,x):(O/n).write_text(json.dumps(x,indent=2)+'\n')
ledger=[]
def create(o):
 m=o['metadata'];m['labels']=label;args=['-n',m['namespace']] if m.get('namespace') else [];assert k(args+['get',o['kind'],m['name'],'--ignore-not-found','-o','json']) is None,'EXISTING_OBJECT_PRESERVED'
 v=k(['create','-f','-','-o','json'],o);ledger.append({'kind':o['kind'],'name':m['name'],'namespace':m.get('namespace'),'uid':v['metadata']['uid'],'apiVersion':v['apiVersion']});save('cosign-kube-ledger.json',ledger)
def role(namespace,roleName,rules,subjects):
 create({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'namespace':namespace,'name':roleName},'rules':rules});create({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'namespace':namespace,'name':roleName},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':roleName},'subjects':subjects})
if sys.argv[1]=='prepare':
 assert not (O/'cosign-kube-ledger.json').exists();x=node("const fs=require('fs'),p='/tmp/runtime-three-"+run+"';console.log(JSON.stringify({pub:JSON.parse(fs.readFileSync(p+'/cosign-test/public.json')),robot:JSON.parse(fs.readFileSync(p+'/harbor-sign.json'))}));")
 create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}});create({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'namespace':ns,'name':name},'automountServiceAccountToken':False});sub=[{'kind':'ServiceAccount','namespace':ns,'name':name}]
 role(ns,run+'-dryrun',[{'apiGroups':[''],'resources':['pods'],'verbs':['create']}],sub);role('data-infra',run+'-lease-read',[{'apiGroups':['coordination.k8s.io'],'resources':['leases'],'resourceNames':['platform-heavy'],'verbs':['get']}],sub)
 cfg={'auths':{'core.harbor.domain':{'auth':base64.b64encode((x['robot']['username']+':'+x['robot']['password']).encode()).decode()}}};create({'apiVersion':'v1','kind':'Secret','metadata':{'namespace':'devsecops-system','name':secret},'type':'kubernetes.io/dockerconfigjson','data':{'.dockerconfigjson':base64.b64encode(json.dumps(cfg).encode()).decode()}})
 role('devsecops-system',run+'-test-registry-read',[{'apiGroups':[''],'resources':['secrets'],'resourceNames':[secret],'verbs':['get']}],[{'kind':'ServiceAccount','namespace':'devsecops-system','name':'kyverno-admission-controller'}])
 original=json.load(open(O/'production-signature-policy-before.json'));spec=original['spec'];spec['rules'][0]['match']['any'][0]['resources'].pop('namespaces');image=spec['rules'][0]['verifyImages'][0];image['imageReferences']=['core.harbor.domain/petclinic/signature-fixtures@sha256:*'];image['attestors'][0]['entries'][0]['keys']['publicKeys']=x['pub']['publicKey'];image['imageRegistryCredentials']['secrets']=[secret]
 create({'apiVersion':'kyverno.io/v1','kind':'Policy','metadata':{'namespace':ns,'name':'devsecops-signed-images','annotations':{'pod-policies.kyverno.io/autogen-controllers':'none'}},'spec':spec})
 token=k(['-n',ns,'create','token',name,'--duration=20m','-o','json'])['status']['token'];ca=k(['-n',ns,'get','configmap','kube-root-ca.crt','-o','json'])['data']['ca.crt'];config={'apiVersion':'v1','kind':'Config','clusters':[{'name':'v','cluster':{'server':'https://kubernetes.default.svc','certificate-authority-data':base64.b64encode(ca.encode()).decode()}}],'users':[{'name':'v','user':{'token':token}}],'contexts':[{'name':'v','context':{'cluster':'v','user':'v'}}],'current-context':'v'}
 node("const fs=require('fs'),x=JSON.parse(fs.readFileSync(0)),p='/tmp/runtime-three-"+run+"';fs.writeFileSync(p+'/cosign-kubeconfig',JSON.stringify(x),{mode:384});console.log('{}');",config)
 public={'validationRunId':run,'namespace':ns,'identity':'system:serviceaccount:'+ns+':'+name,'policy':'devsecops-signed-images','policyScope':'NAMESPACED_VALIDATION_ONLY','publicKeySha256':x['pub']['publicKeySha256'],'registrySecretName':secret,'productionKeyAccess':0,'objects':ledger};save('cosign-kube-public.json',public);node("const fs=require('fs'),x=JSON.parse(fs.readFileSync(0));fs.writeFileSync('/tmp/runtime-three-"+run+"/cosign-kube-public.json',JSON.stringify(x));console.log('{}');",public);print('COSIGN_MIN_RBAC_AND_NAMESPACED_TEST_TRUST_READY')
else:
 ledger=json.load(open(O/'cosign-kube-ledger.json'));removed=[]
 for kind in ['Policy','RoleBinding','Role','Secret','ServiceAccount','Namespace']:
  for o in [x for x in ledger if x['kind']==kind]:
   a=['-n',o['namespace']] if o['namespace'] else [];v=k(a+['get',kind,o['name'],'--ignore-not-found','-o','json']);
   if v is None:removed.append({**o,'alreadyAbsent':True});continue
   assert v['metadata']['uid']==o['uid'] and v['metadata']['labels']['runtime-validation-run']==run
   group='/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'];plural={'Policy':'policies','Role':'roles','RoleBinding':'rolebindings','Secret':'secrets','ServiceAccount':'serviceaccounts','Namespace':'namespaces'}[kind];path=group+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural+'/'+o['name'];k(['delete','--raw',path,'-f','-'],{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':o['uid']}})
   for _ in range(100):
    if k(a+['get',kind,o['name'],'--ignore-not-found','-o','json']) is None:break
    time.sleep(.25)
   else:raise RuntimeError('COSIGN_CLEANUP_NOT_PROVEN')
   removed.append(o)
 state=node("const fs=require('fs'),p='/tmp/runtime-three-"+run+"';for(const n of ['cosign-kubeconfig','cosign-kube-public.json'])fs.rmSync(p+'/'+n,{force:true});console.log(JSON.stringify({kubeTokenRemoved:!fs.existsSync(p+'/cosign-kubeconfig'),remainingNames:fs.existsSync(p)?fs.readdirSync(p):[]}));");save('cosign-kube-cleanup.json',{'removed':removed,**state});print('COSIGN_TEST_KUBERNETES_OBJECTS_REMOVED')
