// Non-release target mapping. Real Kubernetes objects/responses only, no mocks.
import {fail} from '../summary-v2/codec.mjs';
export function validateZapBoundary(c){
 if(c?.sourceId!=='zap'||!/^rf4-\d{8}-[a-f0-9]{6}$/.test(c.validationRunId)||c.namespace!==c.validationRunId||!Number.isSafeInteger(c.build)||c.server!=='https://kubernetes.default.svc'||!c.kubeconfig?.startsWith('/tmp/runtime-four-credentials-'+c.validationRunId+'/')||!c.allowedImage?.includes('@sha256:')||!c.targetImage?.includes('@sha256:')||!/^10\.43\.\d+\.\d+$/.test(c.targetServiceIP??'')||c.productionServiceIP===c.targetServiceIP||c.productionDatabaseAllowed!==false||c.productionTargetAllowed!==false)fail('ZAP_BOUNDARY_ERROR: explicit isolated target and minimum identity required');return c;
}
export function mapZapCall(args,input,c,objects){
 validateZapBoundary(c);const a=args.filter(x=>!x.startsWith('--request-timeout='));let body=input;
 if(a[0]==='create'&&JSON.stringify(a)===JSON.stringify(['create','-f','-','-o','json'])){
  let p;try{p=JSON.parse(input);}catch{fail('ZAP_BOUNDARY_ERROR: invalid Pod');}
  if(p.kind!=='Pod'||p.metadata?.namespace!=='devsecops-execution'||!p.metadata?.name?.startsWith('zap-'+c.build+'-')||p.spec?.automountServiceAccountToken!==false||p.spec?.hostNetwork||p.spec?.hostPID||p.spec?.hostIPC||p.spec?.volumes?.some(v=>!v.emptyDir)||p.spec?.containers?.length!==1||p.spec.containers[0].image!==c.allowedImage||p.spec.containers[0].securityContext?.allowPrivilegeEscalation!==false||p.spec.containers[0].securityContext?.readOnlyRootFilesystem!==true||!p.spec.securityContext?.runAsNonRoot)fail('ZAP_BOUNDARY_ERROR: scanner Pod differs from frozen safe boundary');
  p.metadata.namespace=c.namespace;p.metadata.labels['runtime-validation-run']=c.validationRunId;body=Buffer.from(JSON.stringify(p));return {action:'create',name:p.metadata.name,args:a,input:body,namespace:c.namespace};
 }
 if(a[0]==='-n'&&a[1]==='petclinic'){
  if(a.length===6&&a[2]==='get'&&['deploy','service'].includes(a[3])&&a[4]==='petclinic'&&a[5]==='-o')fail('ZAP_BOUNDARY_ERROR: incomplete target query');
  if(a.length===7&&a[2]==='get'&&['deploy','service'].includes(a[3])&&a[4]==='petclinic'&&a[5]==='-o'&&a[6]==='json')return {action:'read-target',args:['-n',c.namespace,...a.slice(2)],input:body,namespace:c.namespace};
 }
 if(a[0]==='-n'&&a[1]==='data-infra'&&JSON.stringify(a.slice(2))==='["get","lease","platform-heavy","-o","json"]')return {action:'read-lease',args:a,input:body};
 if(a[0]==='-n'&&a[1]==='devsecops-execution'){
  const b=a.slice(2),name=b[0]==='wait'?b[2]?.slice(4):b[2],o=objects.find(o=>o.name===name);
  if(!o)fail('ZAP_BOUNDARY_ERROR: foreign Pod');
  const allowed=(b[0]==='get'&&b[1]==='pod'&&['["-o","json"]','["--ignore-not-found","-o","name"]'].includes(JSON.stringify(b.slice(3))))||(b[0]==='exec'&&b[1]==='-i'&&b[3]==='--')||(b[0]==='wait'&&b[1]==='--for=condition=Ready'&&b[2]==='pod/'+name&&b[3]==='--timeout=180s'&&b.length===4);
  if(allowed)return {action:b[0],name,args:['-n',c.namespace,...b],input:body,namespace:c.namespace,uid:o.uid};
 }
 if(a[0]==='delete'&&a[1]==='--raw'&&a.length===5&&a[3]==='-f'&&a[4]==='-'){
  const o=objects.find(o=>a[2]===`/api/v1/namespaces/devsecops-execution/pods/${o.name}`);let v;try{v=JSON.parse(input);}catch{}
  if(o&&v?.preconditions?.uid===o.uid)return {action:'delete',name:o.name,args:['delete','--raw',`/api/v1/namespaces/${c.namespace}/pods/${o.name}`,'-f','-'],input:body,namespace:c.namespace,uid:o.uid};
 }
 fail('ZAP_BOUNDARY_ERROR: production fallback or unapproved action');
}
