from pathlib import Path
import json,subprocess,shlex,base64,sys,time
O=Path('evidence/2026-11-03/runtime-final-four');run=json.load(open(O/'run.json'))['validationRunId'];ns=run;name='runtime-executor'
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def k(args,obj=None,timeout=40):
 p=subprocess.run(SSH+['sudo -n kubectl '+shlex.join(args)],input=json.dumps(obj).encode() if obj is not None else None,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError('ISOLATED_API_FAILED '+args[0]+' '+p.stderr.decode()[-600:])
 return json.loads(p.stdout) if p.stdout.strip() else None
def save(n,x):(O/n).write_text(json.dumps(x,indent=2)+'\n')
ledger=[]
def create(o):
 meta=o['metadata'];meta.setdefault('labels',{})['runtime-validation-run']=run
 assert k((['-n',meta['namespace']] if meta.get('namespace') else [])+['get',o['kind'],meta['name'],'--ignore-not-found','-o','json']) is None
 v=k(['create','-f','-','-o','json'],o);ledger.append({'kind':v['kind'],'apiVersion':v['apiVersion'],'name':meta['name'],'namespace':meta.get('namespace'),'uid':v['metadata']['uid']});save('zap-object-ledger.json',ledger);return v
action=sys.argv[1] if __name__=='__main__' and len(sys.argv)>1 else None
if action=='prepare':
 assert not (O/'zap-object-ledger.json').exists();assert k(['get','namespace',ns,'--ignore-not-found','-o','json']) is None
 prod=k(['-n','petclinic','get','deployment','petclinic','-o','json']);image=next(c['image'] for c in prod['spec']['template']['spec']['containers'] if c['name']=='petclinic');prodsvc=k(['-n','petclinic','get','service','petclinic','-o','json'])
 save('zap-before-state.json',{'namespaceAbsent':True,'prodDeploymentUid':prod['metadata']['uid'],'prodDeploymentGeneration':prod['metadata']['generation'],'productionServiceIP':prodsvc['spec']['clusterIP'],'validationImage':image,'productionSecretReads':0})
 create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}})
 create({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'deny-all','namespace':ns},'spec':{'podSelector':{},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[]}})
 create({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'scanner-to-validation-only','namespace':ns},'spec':{'podSelector':{'matchLabels':{'petclinic.devops.local/scan-kind':'zap'}},'policyTypes':['Egress'],'egress':[{'to':[{'podSelector':{'matchLabels':{'runtime-validation-app':run}}}],'ports':[{'protocol':'TCP','port':8080}]}]}})
 create({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'app-from-validation-scanner','namespace':ns},'spec':{'podSelector':{'matchLabels':{'runtime-validation-app':run}},'policyTypes':['Ingress'],'ingress':[{'from':[{'podSelector':{'matchLabels':{'petclinic.devops.local/scan-kind':'zap'}}}],'ports':[{'protocol':'TCP','port':8080}]}]}})
 env={'SPRING_PROFILES_ACTIVE':'default','SPRING_DATASOURCE_URL':'jdbc:h2:mem:runtimevalidation;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE','SPRING_DATASOURCE_DRIVER_CLASS_NAME':'org.h2.Driver','SPRING_DATASOURCE_USERNAME':'sa','SPRING_DATASOURCE_PASSWORD':'','SPRING_SQL_INIT_MODE':'always','SPRING_DOCKER_COMPOSE_ENABLED':'false','MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE':'health','JAVA_TOOL_OPTIONS':'-Xms64m -Xmx384m -XX:ActiveProcessorCount=2','APPLICATION_VERSION':run}
 create({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'petclinic','namespace':ns},'spec':{'replicas':1,'selector':{'matchLabels':{'runtime-validation-app':run}},'template':{'metadata':{'labels':{'runtime-validation-app':run,'runtime-validation-run':run}},'spec':{'nodeSelector':{'kubernetes.io/hostname':'devops','kubernetes.io/arch':'arm64'},'automountServiceAccountToken':False,'terminationGracePeriodSeconds':20,'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'petclinic','image':image,'imagePullPolicy':'IfNotPresent','ports':[{'containerPort':8080}],'env':[{'name':a,'value':b} for a,b in env.items()],'resources':{'requests':{'cpu':'100m','memory':'512Mi'},'limits':{'cpu':'2','memory':'768Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'tmp','mountPath':'/tmp'}],'startupProbe':{'httpGet':{'path':'/actuator/health','port':8080},'periodSeconds':5,'failureThreshold':36},'readinessProbe':{'httpGet':{'path':'/actuator/health','port':8080},'periodSeconds':5}}],'volumes':[{'name':'tmp','emptyDir':{'sizeLimit':'128Mi'}}]}}}})
 service=create({'apiVersion':'v1','kind':'Service','metadata':{'name':'petclinic','namespace':ns},'spec':{'selector':{'runtime-validation-app':run},'ports':[{'port':80,'targetPort':8080}]}})
 create({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':name,'namespace':ns},'automountServiceAccountToken':False})
 for scope,rules in [(ns,[{'apiGroups':[''],'resources':['pods'],'verbs':['create','get','list','watch','delete']},{'apiGroups':[''],'resources':['pods/exec'],'verbs':['create','get']},{'apiGroups':[''],'resources':['services'],'resourceNames':['petclinic'],'verbs':['get']},{'apiGroups':['apps'],'resources':['deployments'],'resourceNames':['petclinic'],'verbs':['get']}]),('data-infra',[{'apiGroups':['coordination.k8s.io'],'resources':['leases'],'resourceNames':['platform-heavy'],'verbs':['get']}])]:
  role=run+'-zap';create({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':role,'namespace':scope},'rules':rules});create({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':role,'namespace':scope},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':role},'subjects':[{'kind':'ServiceAccount','name':name,'namespace':ns}]})
 token=k(['-n',ns,'create','token',name,'--duration=20m','-o','json'])['status']['token'];ca=k(['-n',ns,'get','configmap','kube-root-ca.crt','-o','json'])['data']['ca.crt']
 cfg={'apiVersion':'v1','kind':'Config','clusters':[{'name':'validation','cluster':{'server':'https://kubernetes.default.svc','certificate-authority-data':base64.b64encode(ca.encode()).decode()}}],'users':[{'name':'validation','user':{'token':token}}],'contexts':[{'name':'validation','context':{'cluster':'validation','user':'validation'}}],'current-context':'validation'}
 public={'validationRunId':run,'namespace':ns,'targetImage':image,'targetServiceIP':service['spec']['clusterIP'],'productionServiceIP':prodsvc['spec']['clusterIP'],'credentialIdentity':'system:serviceaccount:'+ns+':'+name,'server':'https://kubernetes.default.svc','tokenLifetimeSeconds':1200,'productionDatabaseAllowed':False,'productionTargetAllowed':False}
 node="const fs=require('fs'),x=JSON.parse(fs.readFileSync(0)),p='/tmp/runtime-four-credentials-'+x.public.validationRunId;fs.mkdirSync(p,{mode:448});fs.writeFileSync(p+'/executor.kubeconfig',JSON.stringify(x.config),{mode:384});fs.writeFileSync(p+'/public-binding.json',JSON.stringify(x.public),{mode:384});console.log('ZAP_MIN_IDENTITY_STAGED');"
 p=subprocess.run(SSH+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(node)],input=json.dumps({'config':cfg,'public':public}).encode(),capture_output=True,timeout=25);assert p.returncode==0;save('zap-public-identity.json',public)
 print('ZAP_VALIDATION_NAMESPACE_AND_TARGET_CREATED')
elif action=='ready':
 v=k(['-n',ns,'get','deployment','petclinic','-o','json']);pods=k(['-n',ns,'get','pods','-o','json']);save('zap-target-observation.json',{'deploymentUid':v['metadata']['uid'],'readyReplicas':v['status'].get('readyReplicas',0),'pods':[{'name':p['metadata']['name'],'uid':p['metadata']['uid'],'phase':p['status']['phase'],'conditions':p['status'].get('conditions'),'containerStatuses':[{a:c.get(a) for a in ['name','ready','restartCount','image','imageID','state']} for c in p['status'].get('containerStatuses',[])]} for p in pods['items']]});print(json.dumps({'ready':v['status'].get('readyReplicas',0)}))
elif action=='cleanup':
 ledger=json.load(open(O/'zap-object-ledger.json'));pods=k(['-n',ns,'get','pods','-o','json']);assert all(p['metadata']['labels'].get('runtime-validation-app')==run for p in pods['items']),'SCANNER_OR_FOREIGN_POD_REMAINS_STOP'
 plural={'Namespace':'namespaces','NetworkPolicy':'networkpolicies','Deployment':'deployments','Service':'services','ServiceAccount':'serviceaccounts','Role':'roles','RoleBinding':'rolebindings'};removed=[]
 # Check for foreign resources before deleting the namespace. Controller-created
 # ReplicaSets/Pods must belong to our recorded Deployment; no PVC is expected.
 deploymentUid=next(o['uid'] for o in ledger if o['kind']=='Deployment')
 replicas=k(['-n',ns,'get','replicasets','-o','json'])['items'];replicaUids={r['metadata']['uid'] for r in replicas if any(x.get('uid')==deploymentUid for x in r['metadata'].get('ownerReferences',[]))};assert len(replicaUids)==len(replicas)
 assert all(any(x.get('uid') in replicaUids for x in p['metadata'].get('ownerReferences',[])) for p in pods['items'])
 for resource in ['persistentvolumeclaims','services','deployments','roles','rolebindings','serviceaccounts','configmaps','networkpolicies']:
  listing=k(['-n',ns,'get',resource,'-o','json'])['items']
  for x in listing:
   meta=x['metadata'];known=any(o['uid']==meta['uid'] for o in ledger);automatic=(resource=='serviceaccounts' and meta['name']=='default')or(resource=='configmaps' and meta['name']=='kube-root-ca.crt');assert known or automatic,'FOREIGN_RESOURCE_STOP '+resource+'/'+meta['name']
 save('zap-precleanup-ownership.json',{'namespace':ns,'deploymentUid':deploymentUid,'allForeignWorkloadChecksPassed':True,'replicaSetUids':sorted(replicaUids),'pvcs':0})
 for kind in ['Deployment','Service','RoleBinding','Role','ServiceAccount','NetworkPolicy','Namespace']:
  for o in [v for v in ledger if v['kind']==kind]:
   v=k((['-n',o['namespace']] if o['namespace'] else [])+['get',kind,o['name'],'-o','json']);assert v['metadata']['uid']==o['uid'] and v['metadata']['labels']['runtime-validation-run']==run
   prefix='/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'];endpoint=prefix+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural[kind]+'/'+o['name'];k(['delete','--raw',endpoint,'-f','-'],{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':o['uid']}})
   for _ in range(80):
    if k((['-n',o['namespace']] if o['namespace'] else [])+['get',kind,o['name'],'--ignore-not-found','-o','json']) is None:break
    time.sleep(.5)
   else:raise RuntimeError('DELETE_NOT_CONFIRMED '+kind)
   removed.append(o)
 node="const fs=require('fs'),p='/tmp/runtime-four-credentials-'+process.argv[1];fs.rmSync(p,{recursive:true});console.log(JSON.stringify({tokenDirectoryRemoved:!fs.existsSync(p)}));"
 p=subprocess.run(SSH+['sudo -n kubectl exec -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(node)+' '+shlex.quote(run)],capture_output=True,text=True,timeout=25);assert p.returncode==0;save('zap-cleanup.json',{'objectsRemoved':removed,'namespaceRemoved':True,**json.loads(p.stdout),'productionObjectsDeleted':0});print('ZAP_FIXTURE_CLEANED')
