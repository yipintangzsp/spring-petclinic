import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {cli} from './terraform-ci.mjs';

const owner='terraform-remote-lab',lab='tf-remote-lab',store='terraform-state';
const address='kubernetes_config_map_v1.environment',probe='terraform_data.coordination_probe[0]';
const secret='tfstate-default-petclinic-remote-v1',leaseName='lock-'+secret;
const source='infra/devops-lab/iac/remote';
const digest=v=>crypto.createHash('sha256').update(v).digest('hex');
export function inspectRemotePlan(plan,cleanup=false){
 const changes=[];
 if(plan.resource_changes?.length!==2||new Set(plan.resource_changes.map(c=>c.address)).size!==2)throw Error('Exactly the demo ConfigMap and bounded probe must be present');
 for(const c of plan.resource_changes??[]){
  if(![address,probe].includes(c.address))throw Error('Foreign remote state resource; preserved');
  const actions=c.change.actions,after=c.change.after;
  if(c.address===address){
   if(!['["no-op"]','["create"]','["update"]'].includes(JSON.stringify(actions)))throw Error('ConfigMap removal/replacement is forbidden');
   if(after?.metadata?.[0]?.name!=='environment-manifest'||after.metadata[0].namespace!==lab||after.metadata[0].labels?.['petclinic.devops.local/owner']!==owner||JSON.stringify(Object.keys(after.data??{}).sort())!==JSON.stringify(['config_revision','managed_by','scenario'])||after.data.config_revision!=='v1'||after.data.managed_by!=='terraform'||after.data.scenario!=='petclinic-devops-study')throw Error('Unexpected ConfigMap scope/data');
  }else if(JSON.stringify(actions)!==(cleanup?'["delete"]':'["create"]'))throw Error('Only the bounded state-only coordination probe may be created/removed');
  if(JSON.stringify(actions)!=='["no-op"]')changes.push({address:c.address,actions});
 }
 if(cleanup&&(changes.length!==1||changes[0].address!==probe))throw Error('Cleanup may remove only the state-only probe');
 if(!cleanup&&!changes.some(c=>c.address===probe))throw Error('A new bounded probe is required to test the real apply lock');
 return changes;
}
export function validateBootstrap(doc){
 const expected=new Set(['Namespace/terraform-state','Namespace/tf-remote-lab','ResourceQuota/terraform-state/terraform-budget','ResourceQuota/tf-remote-lab/terraform-budget','ServiceAccount/tf-remote-lab/terraform-runner','Role/terraform-state/terraform-runtime','Role/tf-remote-lab/terraform-runtime','RoleBinding/terraform-state/terraform-runtime','RoleBinding/tf-remote-lab/terraform-runtime']);
 if(doc.items?.length!==expected.size)throw Error('Unexpected bootstrap resource count');
 for(const x of doc.items){
  const m=x.metadata,key=[x.kind,m.namespace,m.name].filter(Boolean).join('/');
  if(!expected.delete(key)||m.labels?.['petclinic.devops.local/owner']!==owner)throw Error('Unexpected bootstrap scope/owner');
  if(x.kind==='Role'){
   const wants=m.namespace===store?[['','secrets'],['coordination.k8s.io','leases']]:[['','configmaps']];
   if(x.rules.length!==wants.length||x.rules.some((r,i)=>JSON.stringify(r.apiGroups)!==JSON.stringify([wants[i][0]])||JSON.stringify(r.resources)!==JSON.stringify([wants[i][1]])||JSON.stringify(r.verbs)!=='["get","list","create","update","patch","delete"]'))throw Error('Unexpected runtime permissions');
  }
  if(x.kind==='RoleBinding'&&(JSON.stringify(x.subjects)!==JSON.stringify([{kind:'ServiceAccount',name:'terraform-runner',namespace:lab}])||x.roleRef.kind!=='Role'||x.roleRef.name!=='terraform-runtime'||x.roleRef.apiGroup!=='rbac.authorization.k8s.io'))throw Error('Unexpected binding');
  if(x.kind==='ServiceAccount'&&x.automountServiceAccountToken!==false)throw Error('No automatic long-lived credential mounts');
  if(x.kind==='ResourceQuota'){
   const h=x.spec.hard;
   for(const k of ['pods','persistentvolumeclaims','services','requests.storage'])if(h[k]!=='0')throw Error('No compute/storage growth permitted');
   if(h.secrets!==(m.namespace===store?'4':'0')||h['count/leases.coordination.k8s.io']!==(m.namespace===store?'4':'0')||h.configmaps!=='4')throw Error('Unexpected metadata quota');
  }
 }
}
function call(bin,args,options={}){
 const {expected=[0],...rest}=options;
 const r=spawnSync(bin,args,{encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024,...rest});
 if(r.error||!expected.includes(r.status))throw Error(`${path.basename(bin)} ${args[0]} failed: ${r.error?.message??r.stderr?.slice(-1500)??r.status}`);
 return r;
}
function kube(args,input){return call('kubectl',['--request-timeout=10s',...args],{input}).stdout.trim();}
function bootstrap(){
 const doc=JSON.parse(fs.readFileSync(path.join(source,'bootstrap.json'),'utf8'));validateBootstrap(doc);
 for(const x of doc.items){
  const raw=kube(['get',x.kind,x.metadata.name,...(x.metadata.namespace?['-n',x.metadata.namespace]:[]),'--ignore-not-found','-o','json']);
  if(raw&&JSON.parse(raw).metadata.labels?.['petclinic.devops.local/owner']!==owner)throw Error('Existing foreign bootstrap object preserved');
 }
 kube(['apply','-f','-'],JSON.stringify(doc));
 return [store,lab].map(n=>{const x=JSON.parse(kube(['get','ns',n,'-o','json']));return {name:n,uid:x.metadata.uid};});
}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
export async function run(){
 process.umask(0o077);
 const build=process.env.BUILD_NUMBER,home=process.env.JENKINS_HOME;
 if(!home||!/^\d+$/.test(build??''))throw Error('Explicit Jenkins execution required');
 const holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${build}`;
 if(JSON.parse(kube(['-n','data-infra','get','lease','platform-heavy','-o','json'])).spec.holderIdentity!==holder)throw Error('Existing outer Jenkins heavy Lease required');
 const namespaces=bootstrap(),bin=cli(home);
 const token=kube(['-n',lab,'create','token','terraform-runner','--duration=10m']);
 const identity=JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
 if(identity.sub!==`system:serviceaccount:${lab}:terraform-runner`||identity.exp-Date.now()/1000>1200||identity.exp-Date.now()/1000<480)throw Error('Unexpected scoped token lifetime/identity');
 const ca=fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt','utf8');
 const api=(method,url,body,auth=true)=>new Promise((resolve,reject)=>{
  const req=https.request('https://kubernetes.default.svc'+url,{method,ca,headers:{...(auth?{Authorization:'Bearer '+token}:{}),'Content-Type':'application/json'},timeout:10000},res=>{
   let text='';res.on('data',c=>text+=c);res.on('end',()=>{let data;try{data=JSON.parse(text);}catch{data={};}resolve({status:res.statusCode,data});});
  });req.on('error',reject);req.on('timeout',()=>req.destroy(Error('API timeout')));req.end(body?JSON.stringify(body):undefined);
 });
 const requireApi=async(method,url,body,status=200)=>{const x=await api(method,url,body);if(x.status!==status)throw Error(`Scoped API ${method} ${url}: HTTP ${x.status}`);return x.data;};
 const permissions=[];
 for(const [namespace,group,resource,verb,allowed] of [[lab,'','configmaps','create',true],[store,'','secrets','get',true],[store,'coordination.k8s.io','leases','update',true],['petclinic','','configmaps','create',false],[lab,'','secrets','get',false],[lab,'apps','deployments','create',false],['','','namespaces','delete',false]]){
  const v=await requireApi('POST','/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',{apiVersion:'authorization.k8s.io/v1',kind:'SelfSubjectAccessReview',spec:{resourceAttributes:{namespace,group,resource,verb}}},201);
  if(v.status.allowed!==allowed)throw Error('Runtime RBAC differs from expected scope');permissions.push({namespace,group,resource,verb,allowed});
 }
 const forbidden=[];
 for(const url of ['/api/v1/namespaces/petclinic/configmaps',`/api/v1/namespaces/${lab}/secrets`]){const x=await api('GET',url);if(x.status!==403)throw Error('Out-of-scope read was not rejected');forbidden.push({path:url,http_status:x.status});}
 const anon=await api('GET',`/api/v1/namespaces/${store}/secrets`,undefined,false);if(![401,403].includes(anon.status))throw Error('Anonymous state access not rejected');
 const cmPath=`/api/v1/namespaces/${lab}/configmaps/environment-manifest`,secretPath=`/api/v1/namespaces/${store}/secrets/${secret}`,leasePath=`/apis/coordination.k8s.io/v1/namespaces/${store}/leases/${leaseName}`;
 const cmBefore=await api('GET',cmPath),secretBefore=await api('GET',secretPath);
 if(![200,404].includes(cmBefore.status)||![200,404].includes(secretBefore.status))throw Error('Unexpected existing resource status');
 if(cmBefore.status===200&&(cmBefore.data.metadata.labels?.['petclinic.devops.local/owner']!==owner||secretBefore.status!==200))throw Error('Untracked or foreign ConfigMap preserved');
 if(secretBefore.status===200&&secretBefore.data.metadata.labels?.['petclinic.devops.local/owner']!==owner)throw Error('Existing foreign state preserved');
 const root=path.join(home,'terraform-runs');fs.mkdirSync(root,{recursive:true,mode:0o700});
 const work=fs.mkdtempSync(path.join(root,`remote-${build}-`)),cache=path.join(home,'tools/terraform/provider-cache');fs.mkdirSync(cache,{recursive:true,mode:0o700});
 const dirs=['a','b'].map(n=>{const d=path.join(work,n);fs.mkdirSync(d,{mode:0o700});fs.mkdirSync(path.join(d,'home'),{mode:0o700});fs.copyFileSync(path.join(source,'main.tf'),path.join(d,'main.tf'));fs.copyFileSync('infra/devops-lab/iac/terraform/.terraform.lock.hcl',path.join(d,'.terraform.lock.hcl'));fs.writeFileSync(path.join(d,'home/public-kubeconfig.json'),JSON.stringify({apiVersion:'v1',kind:'Config',clusters:[{name:'local',cluster:{server:'https://kubernetes.default.svc','certificate-authority-data':Buffer.from(ca).toString('base64')}}],users:[{name:'scoped',user:{}}],contexts:[{name:'scoped',context:{cluster:'local',user:'scoped'}}],'current-context':'scoped'}));return d;});
 const scrub=s=>s.replaceAll(token,'[REDACTED]');
 const cookies=Object.fromEntries(Object.entries(process.env).filter(([k])=>/^(JENKINS_(SERVER|NODE)_COOKIE|HUDSON_COOKIE|BUILD_(ID|TAG))$/.test(k)));
 const environment=dir=>({...cookies,PATH:process.env.PATH,HOME:path.join(dir,'home'),LANG:'C.UTF-8',TF_IN_AUTOMATION:'1',TF_INPUT:'0',CHECKPOINT_DISABLE:'1',TF_PLUGIN_CACHE_DIR:cache,GOMAXPROCS:'1',GOMEMLIMIT:'384MiB',KUBE_HOST:'https://kubernetes.default.svc',KUBE_TOKEN:token,KUBE_CLUSTER_CA_CERT_DATA:ca,KUBE_IN_CLUSTER_CONFIG:'false',KUBE_CONFIG_PATH:path.join(dir,'home/public-kubeconfig.json')});
 const vars=enabled=>{for(const d of dirs)fs.writeFileSync(path.join(d,'probe.auto.tfvars.json'),JSON.stringify({coordination_probe:enabled}));};
 const records=[];
 console.log(JSON.stringify({mode:'terraform-shared-state',private_workdir:work}));
 const tf=(which,name,args,expected=[0],extraEnv={})=>{
  const dir=dirs[which],start=Date.now();console.log('TF_REMOTE_STEP '+(which===0?'a':'b')+' '+name);
  const r=spawnSync(bin,args,{cwd:dir,env:{...environment(dir),...extraEnv},encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
  fs.writeFileSync(path.join(dir,name+'.log'),scrub((r.stdout??'')+(r.stderr??'')+(r.error?.message??'')));
  records.push({client:which===0?'a':'b',step:name,exit:r.status,seconds:(Date.now()-start)/1000});fs.writeFileSync(path.join(work,'steps.json'),JSON.stringify(records,null,2));
  if(r.error||!expected.includes(r.status))throw Error('Terraform '+name+' failed; inspect private logs at '+dir);
  return r;
 };
 const state=which=>{const raw=tf(which,'state-pull',['state','pull']).stdout;if(raw.includes(token))throw Error('Credential found in state');const s=JSON.parse(raw);for(const r of s.resources??[])if(!((r.type==='kubernetes_config_map_v1'&&r.name==='environment')||(r.type==='terraform_data'&&r.name==='coordination_probe')))throw Error('Unexpected resource in shared state');return {raw,s,hash:digest(raw)};};
 vars(true);
 for(const [i] of dirs.entries()){
  tf(i,'fmt',['fmt','-check']);tf(i,'init',['init','-input=false','-lockfile=readonly','-no-color']);tf(i,'validate',['validate','-no-color']);
  const meta=fs.readFileSync(path.join(dirs[i],'.terraform/terraform.tfstate'),'utf8');if(meta.includes(token))throw Error('Credential persisted in backend configuration');
 }
 const denied=tf(1,'missing-token-denied',['state','pull'],[1],{KUBE_TOKEN:''});if(!/forbidden|unauthorized/i.test(denied.stderr))throw Error('Missing-token failure did not prove authentication rejection');
 const prior=state(0);if((prior.s.resources??[]).some(r=>r.type==='terraform_data'))throw Error('Prior incomplete coordination probe preserved; inspect state before retry');
 tf(0,'create-plan',['plan','-input=false','-no-color','-parallelism=1','-lock-timeout=3s','-detailed-exitcode','-out=create.tfplan'],[2]);
 const planned=JSON.parse(tf(0,'create-show',['show','-json','create.tfplan']).stdout);if(JSON.stringify(planned).includes(token))throw Error('Credential persisted in plan');const changes=inspectRemotePlan(planned);
 const child=spawn(bin,['apply','-input=false','-no-color','-parallelism=1','create.tfplan'],{cwd:dirs[0],env:environment(dirs[0]),detached:true,stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='',closed=false,lock;child.stdout.on('data',c=>stdout+=c);child.stderr.on('data',c=>stderr+=c);
 const finished=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(code,signal)=>{closed=true;resolve({code,signal});});});
 let interrupted=false,killTimer;
 const interrupt=()=>{interrupted=true;if(!closed){try{process.kill(-child.pid,'SIGINT');}catch{}killTimer=setTimeout(()=>{if(!closed){try{process.kill(-child.pid,'SIGKILL');}catch{}}},10000);}};
 process.once('SIGTERM',interrupt);process.once('SIGINT',interrupt);
 const timer=setTimeout(interrupt,90000);
 let refusal;
 try{
  for(let n=0;n<80;n++){const x=await api('GET',leasePath);if(x.status===200&&x.data.spec?.holderIdentity){lock=x.data;break;}if(closed)break;await sleep(100);}
  if(!lock)throw Error('No active real apply lock observed');
  const blocked=tf(1,'lock-conflict',['plan','-input=false','-no-color','-lock-timeout=1s'],[1]);
  if(!blocked.stderr.includes('Error acquiring the state lock')||!blocked.stderr.includes(lock.spec.holderIdentity))throw Error('Peer failed for a reason other than the observed state lock');
  const still=await requireApi('GET',leasePath);if(still.metadata.uid!==lock.metadata.uid||still.spec.holderIdentity!==lock.spec.holderIdentity)throw Error('Writer lock changed unexpectedly');
  refusal={peer_exit:1,lease_uid:lock.metadata.uid,holder_id:lock.spec.holderIdentity,lock_info:JSON.parse(lock.metadata.annotations['app.terraform.io/lock-info']),writer_was_active:!closed};
  const completed=await finished;if(completed.code!==0||interrupted)throw Error('Writer apply failed/interrupted; preserve remote state and logs');
 }finally{
  clearTimeout(timer);clearTimeout(killTimer);process.removeListener('SIGTERM',interrupt);process.removeListener('SIGINT',interrupt);if(!closed){try{process.kill(-child.pid,'SIGINT');}catch{}await Promise.race([finished,sleep(10000)]);if(!closed){try{process.kill(-child.pid,'SIGKILL');}catch{}await finished;}}
  fs.writeFileSync(path.join(dirs[0],'writer-apply.log'),scrub(stdout+stderr));
 }
 const live=await requireApi('GET',leasePath);if(live.spec?.holderIdentity)throw Error('Writer left an active lock; preserved for investigation');
 tf(1,'repeat',['plan','-input=false','-no-color','-detailed-exitcode','-lock-timeout=3s'],[0]);
 const peer=state(1),writer=state(0);if(peer.hash!==writer.hash||peer.s.lineage!==prior.s.lineage)throw Error('Clients do not share identical remote state');
 vars(false);
 tf(0,'cleanup-plan',['plan','-input=false','-no-color','-detailed-exitcode','-lock-timeout=3s','-out=cleanup.tfplan'],[2]);inspectRemotePlan(JSON.parse(tf(0,'cleanup-show',['show','-json','cleanup.tfplan']).stdout),true);
 tf(0,'cleanup-probe',['apply','-input=false','-no-color','cleanup.tfplan']);
 tf(1,'final-repeat',['plan','-input=false','-no-color','-detailed-exitcode','-lock-timeout=3s'],[0]);
 const finalA=state(0),finalB=state(1);if(finalA.hash!==finalB.hash||finalA.s.resources?.length!==1||finalA.s.resources[0].type!=='kubernetes_config_map_v1')throw Error('Unexpected final state');
 fs.writeFileSync(path.join(work,'state.snapshot.json'),finalA.raw);
 const finalSecret=await requireApi('GET',secretPath),finalCm=await requireApi('GET',cmPath),finalLock=await requireApi('GET',leasePath);
 if(finalLock.spec?.holderIdentity)throw Error('Final state lock remains held');
 if(secretBefore.status===200&&secretBefore.data.metadata.uid!==finalSecret.metadata.uid)throw Error('State Secret was replaced');
 if(cmBefore.status===200&&cmBefore.data.metadata.uid!==finalCm.metadata.uid)throw Error('ConfigMap was replaced');
 const report={status:'success',build:Number(build),source:fs.readFileSync('.git-sha','utf8').trim(),backend:'kubernetes',transport:'TLS with cluster CA verification',state_namespace:store,state_secret:secret,state_secret_uid:finalSecret.metadata.uid,state_lineage:finalA.s.lineage,state_serial:finalA.s.serial,state_sha256:finalA.hash,config_map_uid:finalCm.metadata.uid,namespaces,identity:identity.sub,token_expires_at:new Date(identity.exp*1000).toISOString(),permissions,forbidden_reads:forbidden,anonymous_state_http_status:anon.status,missing_token_terraform_exit:1,plan_changes:changes,lock_contention:refusal,peer_repeat_exit:0,final_repeat_exit:0,probe_removed:true,backend_lock_released:true,writer_stopped:closed,credentials_absent_from_backend_plan_state:true,private_workdir:work,records,at_rest_encryption:'not enabled on current K3s; no sensitive payload stored',bootstrap_identity:'existing privileged Jenkins account; Terraform children receive only scoped short-lived token',persistent_demo_configmap_retained:true,finished_at:new Date().toISOString()};
 fs.mkdirSync('target/platform',{recursive:true});fs.writeFileSync('target/platform/terraform-remote.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))run().catch(e=>{console.error(e.message);process.exitCode=1;});
