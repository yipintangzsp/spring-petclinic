// Fixed nonproduction dispatcher. No Docker, Git token, shell or Kubernetes write.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import {execFileSync} from 'node:child_process';
import {digest} from '../../security/summary-v2/codec.mjs';
const requireOK=(ok,code)=>{if(!ok)throw Error(code);};
requireOK(process.platform==='linux'&&process.getuid()!==0,'LINUX_NONROOT_REQUIRED');
const source=JSON.parse(fs.readFileSync('evidence/jenkins-gitleaks-receipt.json'));
const {receiptDigest,...body}=source;
requireOK(digest(body)===receiptDigest&&source.job===process.env.DEMO_JOB&&source.build===Number(process.env.DEMO_BUILD)&&source.commit===process.env.DEMO_COMMIT&&
 source.policyDecision==='PASS'&&source.scannerExecuted===true&&source.evaluationCount===1,'SAME_BUILD_GATE_REQUIRED');
const proof=source.gateReceipt;
requireOK(proof?.runId===source.runId&&proof.resultDigest===source.resultDigest,'PROOF_BINDING_REQUIRED');
const key=process.env.DEMO_WRITER_KEY;
requireOK(path.isAbsolute(key??'')&&fs.lstatSync(key).isFile()&&fs.statSync(key).uid===process.getuid()&&!(fs.statSync(key).mode&0o077),'KEY_BOUNDARY');
fs.writeFileSync('writer_known_hosts','192.168.1.58 ssh-ed25519 @TRUSTED_HOST_KEY@\n',{flag:'wx',mode:0o400});
const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
 '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','UserKnownHostsFile='+path.resolve('writer_known_hosts'),
 '-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
 'security-gitops-demo@192.168.64.11'];
function operation(action){
 const text=execFileSync('/usr/bin/ssh',[...args,[action,proof.receiptId,proof.receiptDigest,source.build,source.commit].join(' ')],
  {encoding:'utf8',timeout:65000,maxBuffer:32768,env:{PATH:'/usr/bin:/bin',LANG:'C'}});
 const r=JSON.parse(text);requireOK(r.runId===source.runId&&r.resultDigest===source.resultDigest&&r.triggerCommit===source.commit&&r.build===source.build,'SERVER_OPERATION_BINDING');return r;
}
const ca=fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt');
const token=fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token','utf8').trim();
const get=uri=>new Promise((resolve,reject)=>{
 const req=https.request('https://kubernetes.default.svc'+uri,{ca,method:'GET',headers:{Authorization:'Bearer '+token},timeout:5000},res=>{
  let text='';res.on('data',b=>{text+=b;if(text.length>1048576)req.destroy(Error('READ_LIMIT'));});res.on('end',()=>{try{requireOK(res.statusCode===200,'FIXED_READ_DENIED');resolve(JSON.parse(text));}catch(e){reject(e);}});
 });req.on('timeout',()=>req.destroy(Error('FIXED_READ_TIMEOUT')));req.on('error',reject);req.end();
});
async function observe(revision,value){
 const observations=[];
 for(let i=0;i<47;i++){
  const [a,c]=await Promise.all([get('/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/petclinic-gitops-demo'),get('/api/v1/namespaces/devsecops-test/configmaps/petclinic-gitops-demo')]);
  requireOK(a.metadata.uid==='14cddc81-ea96-4789-ba3d-268423a876d9'&&a.spec.source.targetRevision==='security-demo/gitops-20261105'&&a.spec.source.path==='infra/devops-lab/gitops-demo'&&
   a.spec.destination.namespace==='devsecops-test'&&!a.spec.syncPolicy.automated.prune&&c.metadata.uid==='f9280a4d-242c-4c8d-a056-79e48a4d3f0a','DEMO_IDENTITY_CHANGED');
  const record={observedAt:new Date().toISOString(),argoRevision:a.status.sync.revision,sync:a.status.sync.status,health:a.status.health.status,value:c.data['demo-stage'],configMapUid:c.metadata.uid,resourceVersion:c.metadata.resourceVersion};observations.push(record);
  if(record.argoRevision===revision&&record.sync==='Synced'&&record.health==='Healthy'&&record.value===value&&a.status.operationState.phase==='Succeeded'&&a.status.operationState.syncResult.revision===revision)return {verified:true,...record,observations};
  if(i%6===0)console.log('GITOPS_WAIT '+JSON.stringify(record));
  if(i<46)await new Promise(r=>setTimeout(r,5000));
 }
 throw Error('GITOPS_EXACT_REVISION_NOT_OBSERVED');
}
function notifyArgo(operation){
 const payload=JSON.stringify({object_kind:'push',event_name:'push',ref:'refs/heads/security-demo/gitops-20261105',before:operation.beforeCommit,after:operation.afterCommit,
  project:{id:12,default_branch:'main',git_http_url:'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',web_url:'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform'},commits:[]});
 return new Promise((resolve,reject)=>{
  const req=http.request('http://argocd-server.argocd.svc.cluster.local/api/webhook',{method:'POST',timeout:5000,headers:{'Content-Type':'application/json','X-Gitlab-Event':'Push Hook','Content-Length':Buffer.byteLength(payload)}},res=>{
   res.resume();res.on('end',()=>{try{requireOK(res.statusCode===200,'ARGO_NOTIFICATION_DENIED');resolve({http:200,commit:operation.afterCommit,at:new Date().toISOString(),source:'Jenkins bridge to existing Argo native webhook; not GitLab delivery evidence'});}catch(e){reject(e);}});
  });req.on('timeout',()=>req.destroy(Error('ARGO_NOTIFICATION_TIMEOUT')));req.on('error',reject);req.end(payload);
 });
}
let update,updated,restore,restored,updateNotification,restoreNotification,error;
try{update=operation('update-v1');requireOK(update.state==='UPDATED','UPDATE_STATE');console.log('GITOPS_UPDATED_COMMIT '+update.afterCommit);updateNotification=await notifyArgo(update);updated=await observe(update.afterCommit,'updated');}
catch(e){error=e;}
finally{if(update){try{restore=operation('restore-v1');requireOK(restore.state==='RESTORED','RESTORE_STATE');console.log('GITOPS_REVERT_COMMIT '+restore.afterCommit);restoreNotification=await notifyArgo(restore);restored=await observe(restore.afterCommit,'baseline');}catch(e){error??=e;}}}
const result={kind:'JenkinsSameRunGitOpsEvidence',classification:'REAL_CONTROLLED_EXECUTION',job:source.job,build:source.build,triggerCommit:source.commit,
 runId:source.runId,policyDecision:source.policyDecision,resultDigest:source.resultDigest,gateReceipt:proof,update,updated,restore,restored,updateNotification,restoreNotification,
 completedAt:new Date().toISOString(),status:!error&&updated?.verified&&restored?.verified?'SUCCESS':'FAILURE',productionRelease:false,productionRollout:false};
fs.writeFileSync('evidence/jenkins-gitops-receipt.json',JSON.stringify({...result,receiptDigest:digest(result)},null,2),{flag:'wx',mode:0o400});
if(error)throw error;
console.log('CI_CD_VERIFIED '+JSON.stringify({runId:source.runId,updateCommit:update.afterCommit,restoreCommit:restore.afterCommit,resultDigest:source.resultDigest}));
