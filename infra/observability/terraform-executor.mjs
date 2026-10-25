import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {jobSpec,admissionPolicies,namespace} from './terraform-isolation-spec.mjs';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const owner='terraform-isolation';
function kube(args,input){const r=spawnSync('kubectl',['--request-timeout=10s',...args],{input:input===undefined?undefined:JSON.stringify(input),encoding:'utf8',timeout:15000,maxBuffer:4*1024*1024});if(r.status!==0)throw Error('Trusted bootstrap kubectl '+args[0]+': '+r.stderr.slice(-1200));return r.stdout.trim();}
function applyOwned(document){
 for(const x of document.items){const n=x.metadata;const raw=kube(['get',x.kind,n.name,...(n.namespace?['-n',n.namespace]:[]),'--ignore-not-found','-o','json']);if(raw&&JSON.parse(raw).metadata.labels?.['petclinic.devops.local/owner']!==n.labels['petclinic.devops.local/owner'])throw Error('Foreign bootstrap object preserved: '+n.name);}
 kube(['apply','-f','-'],document);
}
function tokenFor(name){return kube(['-n',namespace,'create','token',name,'--duration=10m']);}
export function client(token,options={}){
 const ca=options.ca??fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt');const transport=options.transport??https,origin=options.origin??'https://kubernetes.default.svc';
 return (method,url,body)=>new Promise((resolve,reject)=>{const payload=body===undefined?undefined:Buffer.from(JSON.stringify(body));const r=transport.request(origin+url,{method,ca,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(payload?{'Content-Length':payload.length}:{})},timeout:12000},res=>{let text='';res.on('data',c=>text+=c);res.on('end',()=>{let value;try{value=JSON.parse(text);}catch{value=text;}resolve({status:res.statusCode,value,text});});});r.on('error',reject);r.on('timeout',()=>r.destroy(Error('Scoped API timeout')));r.end(payload);});
}
export function createCanaryServer(){return net.createServer(socket=>{socket.on('error',()=>{});socket.end('terraform-isolation-canary');});}
export async function waitAcceptedAdmission(probe,pause=sleep){
 const errors=[];
 for(let attempt=1;attempt<=30;attempt++){
  const x=await probe();
  if(x.status===201)return {attempts:attempt,errors};
  if(x.status!==403||!String(x.value?.message??'').includes("ValidatingAdmissionPolicy 'terraform-isolation-jobs'"))throw Error('Valid Job dry-run rejected: HTTP '+x.status);
  errors.push({http:x.status,message:String(x.value.message).slice(0,500)});
  if(attempt<30)await pause(1000);
 }
 throw Error('Fixed runtime admission did not become ready within30 attempts');
}
export function observedLog(previous,response){
 if(response.status===200)return response.text||previous;
 if([204,400,404,408,429,500,502,503,504].includes(response.status))return previous;
 throw Error('Owned live logs unavailable: HTTP '+response.status);
}
export function selectOwnedPod(pods,previous,uid,allowRemoved=false){
 if(pods.length>1)throw Error('Unexpected owned Pod set');
 const pod=pods[0]??(allowRemoved?previous:null);
 if(!pod||!pod.metadata.ownerReferences?.some(o=>o.uid===uid)||previous&&pod.metadata.uid!==previous.metadata.uid)throw Error('Unexpected owned Pod set');
 return pod;
}
export async function run(mode){
 if(!['plan','shared','recovery'].includes(mode))throw Error('Explicit isolated mode required');
 const build=process.env.BUILD_NUMBER,holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${build}`;if(!/^\d+$/.test(build??''))throw Error('Explicit build required');
 if(JSON.parse(kube(['-n','data-infra','get','lease','platform-heavy','-o','json'])).spec.holderIdentity!==holder)throw Error('Existing outer heavy Lease required');
 const runtime=JSON.parse(fs.readFileSync('target/platform/terraform-runtime.json')),source=fs.readFileSync('.git-sha','utf8').trim();if(runtime.status!=='success'||runtime.source!==source||runtime.scan.scan_status!=='Success')throw Error('Scanned matching runtime required');
 const promotion=JSON.parse(fs.readFileSync('target/platform/promotion.json'));if(promotion.source!==source)throw Error('Original release gates must complete before execution bootstrap');
 const existing=kube(['get','ns',namespace,'--ignore-not-found','-o','json'])?kube(['-n',namespace,'get','jobs','-o','json']):'';if(existing&&JSON.parse(existing).items?.some(j=>j.status?.active))throw Error('Existing active Job preserved');
 const bootstrap=JSON.parse(fs.readFileSync('infra/devops-lab/iac/isolated/bootstrap.json'));applyOwned(bootstrap);
 const policies=admissionPolicies(runtime.image);applyOwned(policies);
 for(const policy of policies.items.filter(x=>x.kind==='ValidatingAdmissionPolicy')){let ready=false;for(let i=0;i<30;i++){const v=JSON.parse(kube(['get','validatingadmissionpolicy',policy.metadata.name,'-o','json']));if(v.status?.observedGeneration===v.metadata.generation){if(v.status.typeChecking?.expressionWarnings?.length)throw Error('Admission expression warnings: '+JSON.stringify(v.status.typeChecking.expressionWarnings));ready=true;break;}await sleep(1000);}if(!ready)throw Error('Admission policy not compiled');}
 const token=tokenFor('terraform-orchestrator'),payload=JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
 if(payload.sub!==`system:serviceaccount:${namespace}:terraform-orchestrator`||payload.exp-Date.now()/1000>1200)throw Error('Wrong orchestration identity');
 const api=client(token),denied=await api('GET','/api/v1/namespaces/terraform-state/secrets');if(denied.status!==403)throw Error('Orchestrator must not read state credentials');
 const legacyToken=kube(['-n','tf-remote-lab','create','token','terraform-runner','--duration=10m']);if((await client(legacyToken)('GET','/api/v1/namespaces/terraform-state/secrets')).status!==403)throw Error('Legacy runtime privileges still active');
 const ip=os.networkInterfaces().eth0?.find(x=>x.family==='IPv4')?.address;if(!/^10\.42\.0\.\d+$/.test(ip??''))throw Error('Cannot identify local controller canary');
 const server=createCanaryServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(6443,ip,resolve);});
 const baseline=()=>new Promise((resolve,reject)=>{const s=net.connect({host:ip,port:6443,timeout:2000});s.once('connect',()=>{s.destroy();resolve(true);});s.once('error',reject);s.once('timeout',()=>{s.destroy();reject(Error('Canary baseline down'));});});
 const nonce=crypto.randomBytes(4).toString('hex'),evidence={status:'failed',mode,source,build:Number(build),runtime_image:runtime.image,orchestrator_identity:payload.sub,orchestrator_state_read_http:403,legacy_runtime_state_read_http:403,canary_ip:ip,jobs:[],admission_denials:[]};
 const base=jobSpec({name:`tf-${build}-${mode}-${nonce}`,image:runtime.image,mode:mode==='recovery'?'failure':mode,source,api:'https://10.0.0.3:6443',canary:ip});
 const route=`/apis/batch/v1/namespaces/${namespace}/jobs`;
 fs.mkdirSync(path.join(process.env.JENKINS_HOME,'terraform-runs'),{recursive:true,mode:0o700});
 const privateRoot=fs.mkdtempSync(path.join(process.env.JENKINS_HOME,'terraform-runs',`isolated-${build}-${mode}-`));
 const requireStatus=(x,allowed)=>{if(!allowed.includes(x.status))throw Error('Scoped API HTTP '+x.status+': '+String(x.value?.message??'').slice(-1000));return x.value;};
 async function dryRun(job){return api('POST',route+'?dryRun=All',job);}
 async function execute(kind){
  const job=structuredClone(base);job.metadata.name=`tf-${build}-${kind}-${nonce}`;job.metadata.labels['petclinic.devops.local/run']=job.metadata.name;job.spec.template.metadata.labels['petclinic.devops.local/run']=job.metadata.name;job.spec.template.spec.containers[0].env.find(x=>x.name==='EXECUTION_MODE').value=kind;if(kind==='deadline')job.spec.activeDeadlineSeconds=60;
  const created=requireStatus(await api('POST',route,job),[201]),name=created.metadata.name,uid=created.metadata.uid;let terminal,pods=[],observedPod,log='',result;
  const record={name,uid,kind,active_deadline_seconds:job.spec.activeDeadlineSeconds,cleanup_completed:false};evidence.jobs.push(record);
  console.log('TF_ISOLATED_JOB '+name+' UID='+uid);
  try{
   for(let i=0;i<80;i++){
    const [jobReply,podReply]=await Promise.all([api('GET',route+'/'+name),api('GET',`/api/v1/namespaces/${namespace}/pods?labelSelector=`+encodeURIComponent('batch.kubernetes.io/job-name='+name))]);
    const current=requireStatus(jobReply,[200]);if(current.metadata.uid!==uid)throw Error('Job UID changed');
    pods=requireStatus(podReply,[200]).items;
    if(pods.length){
     observedPod=selectOwnedPod(pods,observedPod,uid);Object.assign(record,{pod:observedPod.metadata.name,pod_uid:observedPod.metadata.uid,last_pod_observed_at:new Date().toISOString()});
     const response=await api('GET',`/api/v1/namespaces/${namespace}/pods/${observedPod.metadata.name}/log?limitBytes=262144`);
     if(response.status!==200){record.log_poll_errors??=[];if(record.log_poll_errors.length<20)record.log_poll_errors.push({http:response.status,message:String(response.value?.message??'').slice(0,300),at:new Date().toISOString()});}log=observedLog(log,response);
    }
    if(current.status?.conditions?.some(x=>['Complete','Failed'].includes(x.type)&&x.status==='True')){terminal=current;break;}
    await sleep(2500);
   }
   if(!terminal)throw Error('Isolated Job deadline exceeded');
   const deadlineRemoved=kind==='deadline'&&terminal.status.conditions.some(x=>x.type==='Failed'&&x.status==='True'&&x.reason==='DeadlineExceeded');
   const p=selectOwnedPod(pods,observedPod,uid,deadlineRemoved);
if(p.spec.serviceAccountName!=='terraform-runner'||p.spec.hostPID||p.spec.hostNetwork||p.spec.automountServiceAccountToken!==false||p.spec.volumes.some(v=>v.hostPath||v.persistentVolumeClaim||v.secret))throw Error('Observed Pod not isolated');
   const imageID=p.status.containerStatuses?.[0]?.imageID??'';if(!imageID.includes(runtime.digest))throw Error('Actual runtime image digest differs');
   if(!log)throw Error('Owned logs unavailable before Pod removal: '+JSON.stringify(record.log_poll_errors??[]));
   fs.writeFileSync(path.join(privateRoot,name+'.log'),log,{mode:0o600});
   const lines=log.split('\n').filter(x=>x.startsWith('TF_ISOLATION_REPORT:'));if(lines.length)result=JSON.parse(lines.at(-1).slice('TF_ISOLATION_REPORT:'.length));
   Object.assign(record,{pod:p.metadata.name,pod_uid:p.metadata.uid,image_id:imageID,conditions:terminal.status.conditions,resources:p.spec.containers[0].resources,exit:p.status.containerStatuses[0].state.terminated?.exitCode??null,pod_removed_by_deadline_controller:pods.length===0&&deadlineRemoved,job_created_at:created.metadata.creationTimestamp,job_started_at:terminal.status.startTime??null,job_completed_at:terminal.status.completionTime??null,report:result??null,log_sha256:crypto.createHash('sha256').update(log).digest('hex')});
   if(['plan','shared'].includes(kind)){
    if(!terminal.status.succeeded||result?.status!=='success'||result.source!==source||!result.isolation.network_policy_canary_blocked)throw Error('Isolated business workflow did not pass');
   }else if(kind==='failure'){
    if(!terminal.status.failed||result?.status!=='expected-failure'||!result.before_state_write||p.status.containerStatuses[0].state.terminated?.exitCode!==42)throw Error('Controlled failure not exercised');
   }else if(!terminal.status.conditions.some(x=>x.reason==='DeadlineExceeded')||!log.includes('TF_ISOLATION_HOLD_READY'))throw Error('Actual deadline cleanup not exercised');

  }finally{
   if(log){fs.writeFileSync(path.join(privateRoot,name+'.log'),log,{mode:0o600});record.log_sha256=crypto.createHash('sha256').update(log).digest('hex');}
   const current=await api('GET',route+'/'+name);if(current.status===200){if(current.value.metadata.uid!==uid)throw Error('Refuse cleanup of replacement Job');requireStatus(await api('DELETE',route+'/'+name,{apiVersion:'v1',kind:'DeleteOptions',preconditions:{uid},propagationPolicy:'Foreground'}),[200,202]);}
   let cleaned=false;for(let i=0;i<40;i++){const j=await api('GET',route+'/'+name),p=await api('GET',`/api/v1/namespaces/${namespace}/pods?labelSelector=`+encodeURIComponent('batch.kubernetes.io/job-name='+name));if(j.status===404&&p.status===200&&p.value.items.length===0){cleaned=true;break;}await sleep(500);}record.cleanup_completed=cleaned;if(!cleaned)throw Error('Owned Job/Pod cleanup incomplete');
  }
 }
 try{
  await baseline();evidence.valid_admission_wait=await waitAcceptedAdmission(()=>dryRun(base));
  const mutations={admin_identity:j=>j.spec.template.spec.serviceAccountName='default',host_network:j=>j.spec.template.spec.hostNetwork=true,host_path:j=>j.spec.template.spec.volumes.push({name:'escape',hostPath:{path:'/var/jenkins_home'}}),writable_root:j=>j.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem=false,mutable_image:j=>j.spec.template.spec.containers[0].image='python:latest',bypass_entrypoint:j=>j.spec.template.spec.containers[0].command=['sh','-c','id'],lifecycle_exec:j=>j.spec.template.spec.containers[0].lifecycle={postStart:{exec:{command:['sh','-c','id']}}},token_via_termination:j=>j.spec.template.spec.containers[0].terminationMessagePath='/var/run/terraform-identity/token',privileged:j=>{const c=j.spec.template.spec.containers[0];c.securityContext.privileged=true;c.securityContext.allowPrivilegeEscalation=true;delete c.securityContext.seccompProfile;delete c.securityContext.appArmorProfile;delete j.spec.template.spec.securityContext.seccompProfile;},secret_env:j=>j.spec.template.spec.containers[0].env.push({name:'GITLAB_TOKEN',valueFrom:{secretKeyRef:{name:'fake',key:'token'}}})};
  for(const [name,change] of Object.entries(mutations)){const j=structuredClone(base);change(j);const x=await dryRun(j);if(x.status!==403||!/(terraform-isolation|PodSecurity)/.test(x.value?.message??''))throw Error('Admission did not explicitly reject '+name+': HTTP '+x.status+' '+String(x.value?.message??'').slice(-1200));evidence.admission_denials.push({case:name,http_status:x.status,message:x.value.message});}
  if(mode==='plan'&&kube(['get','ns','tf-devops-lab','--ignore-not-found','-o','json']))throw Error('Existing v1 lab preserved; plan preview requires absent namespace');
  if(mode==='recovery'){await execute('failure');await execute('plan');evidence.controlled_failure_retry_succeeded=true;await execute('deadline');}else await execute(mode);
  await baseline();if(mode==='plan'&&kube(['get','ns','tf-devops-lab','--ignore-not-found','-o','json']))throw Error('Plan created a namespace');
  const remains=requireStatus(await api('GET',route),[200]).items.filter(x=>x.status?.active);if(remains.length)throw Error('Unexpected active isolated Job');
  evidence.status='success';evidence.owned_jobs_and_pods_removed=true;evidence.canary_healthy_before_and_after=true;evidence.private_logs=privateRoot;
 }catch(error){evidence.error=error.message;throw error;}finally{
  await new Promise(resolve=>server.close(resolve));fs.mkdirSync('target/platform',{recursive:true});fs.writeFileSync(`target/platform/terraform-isolated-${mode}.json`,JSON.stringify(evidence,null,2));
 }
 console.log(JSON.stringify(evidence,null,2));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))run(process.argv[2]).catch(e=>{console.error(e.message);process.exitCode=1;});
