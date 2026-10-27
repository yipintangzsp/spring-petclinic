// Borrow the existing CI Lease; never acquire a second lock or remove Sonar data.
import fs from 'node:fs';
import {scannerQueue} from './scanner-queue-reservation.mjs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const ns='data-infra',leaseName='platform-heavy',ownerKey='petclinic.devops.local/analysis-holder',stateKey='petclinic.devops.local/paused-sonar';
const pretest=(process.argv[2]??'').startsWith('pretest-');
const file=pretest?'.devsecops/sonar-pretest-slot.json':'.devsecops/sonar-resource-slot.json';
export function validatePause(sts,lease,uid,holder){
 if(!holder||holder.endsWith('undefined')||lease.spec.holderIdentity!==holder)throw Error('Owned outer Lease required');
 if(sts.metadata.uid!==uid||sts.spec.replicas!==1||sts.status.readyReplicas!==1)throw Error('Original Sonar UID and Ready singleton required');
 if(sts.metadata.annotations?.[ownerKey]||lease.metadata.annotations?.[stateKey])throw Error('Existing resource owner preserved');
 return {uid,replicas:1,holder,leaseUid:lease.metadata.uid};
}
export function otherBuilds(jobs,name,number){return jobs.some(x=>x.lastBuild?.building&&!(x.name===name&&x.lastBuild.number===Number(number)));}
export function validateRestore(sts,state){
 if(sts.metadata.uid!==state.uid)throw Error('Sonar UID changed; retain lock and quiet state');
 const owner=sts.metadata.annotations?.[ownerKey];
 if(owner!==state.holder&&!(state.restored&&owner===undefined&&sts.spec.replicas===state.replicas))throw Error('Foreign or missing Sonar owner preserved');
}
const kube=(a,input)=>{const r=spawnSync('kubectl',['--request-timeout=20s',...a],{input,encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});if(r.status!==0)throw Error(r.stderr.slice(-800));return r.stdout;};
const get=a=>JSON.parse(kube([...a,'-o','json']));
const sleep=()=>new Promise(r=>setTimeout(r,2000));
const relayCode=`const fs=require('fs');(async()=>{const i=JSON.parse(fs.readFileSync(0,'utf8'));const base=process.env.JENKINS_URL;const h={Authorization:'Basic '+Buffer.from(process.env.JENKINS_USER+':'+process.env.JENKINS_PASS).toString('base64')};if(i.method==='POST'){const c=await fetch(base+'/crumbIssuer/api/json',{headers:h,signal:AbortSignal.timeout(5000)});if(!c.ok)throw Error('Crumb unavailable');const x=await c.json();h[x.crumbRequestField]=x.crumb;h.Cookie=c.headers.getSetCookie().map(x=>x.split(';')[0]).join('; ');}const r=await fetch(base+i.path,{method:i.method,headers:h,signal:AbortSignal.timeout(12000)});if(!r.ok)throw Error('Jenkins HTTP '+r.status);console.log(JSON.stringify(i.method==='GET'?await r.json():{status:r.status}));})().catch(e=>{console.error(e.message);process.exit(1)});`;
const jenkins=(path,method='GET')=>JSON.parse(kube(['-n','ns-devops','exec','-i','deploy/github-webhook-relay','--','node','--max-old-space-size=24','-e',relayCode],JSON.stringify({path,method})));
const statePath='/api/json?tree=quietingDown,jobs[name,lastBuild[number,building]]';
const save=s=>{fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync(file,JSON.stringify(s,null,2),{mode:0o600});};
const escape=s=>s.replaceAll('~','~0').replaceAll('/','~1');
function markRestored(s){
 if(pretest){
  const lease=get(['-n',ns,'get','lease',leaseName]);
  if(lease.metadata.uid!==s.leaseUid||lease.spec.holderIdentity!==s.holder)throw Error('Pretest Lease ownership changed');
  const note=lease.metadata.annotations?.[stateKey];
  if(note){if(!JSON.parse(note).pretestPhase||JSON.parse(note).holder!==s.holder)throw Error('Later scanner phase preserved');
   kube(['-n',ns,'patch','lease',leaseName,'--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.leaseUid},{op:'test',path:'/metadata/annotations/'+escape(stateKey),value:note},{op:'remove',path:'/metadata/annotations/'+escape(stateKey)}])]);}
  s.pretestLeaseAnnotationCleared=true;
 }
 s.restored=true;save(s);
}

async function main(){
 const mode=pretest?process.argv[2].slice(8):process.argv[2];
 const holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${process.env.BUILD_NUMBER}`;
 if(!['pause','restore','resume'].includes(mode))throw Error('Use pause/restore/resume');
 if(mode==='resume'){
  const files=['.devsecops/sonar-resource-slot.json','.devsecops/sonar-pretest-slot.json'].filter(f=>fs.existsSync(f));
  if(!files.length)return;
  const states=files.map(f=>JSON.parse(fs.readFileSync(f)));
  if(states.some(s=>!s.restored||s.holder!==holder))throw Error('All scanner phases must be restored before queue release');
  if(kube(['-n',ns,'get','lease',leaseName,'--ignore-not-found','-o','json']).trim())throw Error('Release owned Lease before resuming Jenkins');
  const released=states.some(s=>s.queueReservationRequested)?scannerQueue('release',holder):null;
  for(let i=0;i<states.length;i++){states[i].queueReleased=released;states[i].jenkinsQuietRestored=true;fs.writeFileSync(files[i],JSON.stringify(states[i],null,2),{mode:0o600});}
  console.log('Owned queue reservation removed after all scanner phases restored');return;
 }
 if(pretest&&mode==='restore'&&fs.existsSync(file)){
  const old=JSON.parse(fs.readFileSync(file));if(old.holder!==holder)throw Error('Foreign pretest state preserved');
  if(old.restored){console.log('Pretest scanner already restored; later phases preserved');return;}
 }
 if(pretest&&mode==='restore'&&!fs.existsSync(file)){
  const raw=kube(['-n',ns,'get','lease',leaseName,'--ignore-not-found','-o','json']);
  const note=raw.trim()?JSON.parse(raw).metadata.annotations?.[stateKey]:null;
  if(!note||!JSON.parse(note).pretestPhase){console.log('No owned pretest scanner phase');return;}
 }
 if(mode==='restore'&&!fs.existsSync(file)){const raw=kube(['-n',ns,'get','lease',leaseName,'--ignore-not-found','-o','json']);if(!raw.trim()||!JSON.parse(raw).metadata.annotations?.[stateKey]||JSON.parse(JSON.parse(raw).metadata.annotations[stateKey]).holder!==holder){console.log('No owned scanner resource slot');return;}}
 const lease=get(['-n',ns,'get','lease',leaseName]);
 if(lease.spec.holderIdentity!==holder)throw Error('Current CI does not own outer Lease');
 let sts=get(['-n','sonarqube','get','statefulset','sonarqube-sonarqube']);
 if(mode==='pause'){
  const config=JSON.parse(fs.readFileSync('infra/sonarqube/runtime.json'));
  const s=validatePause(sts,lease,config.statefulSetUid,holder);
  const pod=get(['-n','sonarqube','get','pod','sonarqube-sonarqube-0']);const mount=pod.spec.containers.find(c=>c.name==='sonarqube').volumeMounts.find(m=>m.mountPath==='/opt/sonarqube/data');
  const volume=mount&&pod.spec.volumes.find(v=>v.name===mount.name);if(!volume?.persistentVolumeClaim)throw Error('Persistent Sonar data volume required before pause');
  s.dataClaim=volume.persistentVolumeClaim.claimName;s.originalPodUid=pod.metadata.uid;s.source=fs.readFileSync('.git-sha','utf8').trim();
  const host=process.env.SONAR_HOST_URL;if(new URL(host).hostname!=='sonarqube-sonarqube.sonarqube.svc.cluster.local'||!process.env.SONAR_TOKEN)throw Error('Existing scoped Sonar credential and endpoint required');
  let report;
  if(pretest){
   const prior=jenkins('/job/petclinic-ci/lastSuccessfulBuild/artifact/.devsecops/sonar-resource-slot.json');
   if(!prior.restored||prior.queueProof?.submittedTaskStatus!=='SUCCESS'||!prior.queueProof.submittedTask)throw Error('Prior completed successful analysis proof required for pretest slot');
   report={projectKey:'petclinic',ceTaskId:prior.queueProof.submittedTask};
  }else{
   const gate=JSON.parse(fs.readFileSync('target/platform/sonar-quality.json'));if(gate.gate?.status!=='OK')throw Error('Completed original Sonar quality gate required');
   report=Object.fromEntries(fs.readFileSync('target/sonar/report-task.txt','utf8').trim().split(/\r?\n/).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)];}));
  }
  if(report.projectKey!=='petclinic'||!report.ceTaskId)throw Error('Known project analysis task required');
  const q=await fetch(host+'/api/ce/task?id='+encodeURIComponent(report.ceTaskId),{headers:{Authorization:'Bearer '+process.env.SONAR_TOKEN},signal:AbortSignal.timeout(10000)});if(!q.ok)throw Error('Cannot verify known analysis task HTTP '+q.status);const ce=await q.json();
  if(ce.task?.id!==report.ceTaskId||ce.task.status!=='SUCCESS'||ce.task.componentKey!=='petclinic')throw Error('Known project analysis is not complete');
  const secret=get(['-n','sonarqube','get','secret','sonarqube-sonarqube-monitoring-passcode']);const pass=Buffer.from(secret.data.SONAR_WEB_SYSTEMPASSCODE,'base64').toString();
  const r=await fetch(host+'/api/monitoring/metrics',{headers:{'X-Sonar-Passcode':pass},signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('Existing monitoring identity cannot verify pending queue');
  const pending=(await r.text()).match(/^sonarqube_compute_engine_pending_tasks_total\s+([\d.]+)$/m);if(!pending||Number(pending[1])!==0)throw Error('Global pending queue is not empty');
  const j=jenkins(statePath);if(otherBuilds(j.jobs,process.env.JOB_NAME,process.env.BUILD_NUMBER))throw Error('Another Jenkins build is active');
  s.pretestPhase=pretest;s.originalQuiet=j.quietingDown;s.queueProof={submittedTask:report.ceTaskId,submittedTaskStatus:'SUCCESS',globalPending:0,phase:pretest?'before-test':'after-analysis',scope:'Known platform scans serialized through Jenkins; unregistered external in-progress scans are not globally proven'};s.queueReservationRequested=true;s.paused=false;s.restored=false;s.startedAt=new Date().toISOString();save(s);
  kube(['-n',ns,'patch','lease',leaseName,'--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.leaseUid},{op:'add',path:'/metadata/annotations',value:{...(lease.metadata.annotations??{}),[stateKey]:JSON.stringify(s)}}])]);
  s.queueReservationRequested=true;save(s);s.queueReservation=scannerQueue('reserve',holder);save(s);
  if(pretest){
   const check=await fetch(host+'/api/monitoring/metrics',{headers:{'X-Sonar-Passcode':pass},signal:AbortSignal.timeout(10000)});
   const repeated=check.ok?(await check.text()).match(/^sonarqube_compute_engine_pending_tasks_total\s+([\d.]+)$/m):null;
   if(!repeated||Number(repeated[1])!==0)throw Error('Pending analysis appeared after queue reservation');
   s.queueProof.pendingRecheckedAfterReservation=true;save(s);
  }
  const exclusive=jenkins(statePath);if(exclusive.quietingDown||otherBuilds(exclusive.jobs,process.env.JOB_NAME,process.env.BUILD_NUMBER))throw Error('Exclusive known scanner dispatch not confirmed');
  const patch=[{op:'test',path:'/metadata/uid',value:s.uid},{op:'test',path:'/metadata/resourceVersion',value:sts.metadata.resourceVersion}];
  if(!sts.metadata.annotations)patch.push({op:'add',path:'/metadata/annotations',value:{}});
  patch.push({op:'add',path:'/metadata/annotations/'+escape(ownerKey),value:holder},{op:'replace',path:'/spec/replicas',value:0});
  kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify(patch)]);s.paused=true;save(s);
  for(let i=0;i<60;i++){const raw=kube(['-n','sonarqube','get','pod','sonarqube-sonarqube-0','--ignore-not-found','-o','json']);if(!raw.trim()){s.stoppedAt=new Date().toISOString();save(s);console.log(pretest?'Idle Sonar memory released before tests; prior task complete, known CI exclusive, PVC preserved':'Idle Sonar memory released after completed quality gate; PVC preserved');return;}if(JSON.parse(raw).metadata.uid!==s.originalPodUid)throw Error('Unexpected replacement Sonar pod during pause');await sleep();}
  throw Error('Sonar graceful stop not confirmed');
 }
 const recorded=lease.metadata.annotations?.[stateKey];
 if(!recorded&&!fs.existsSync(file)){console.log('No scanner resource slot to restore');return;}
 let s=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):JSON.parse(recorded);
 if(s.holder!==holder||s.leaseUid!==lease.metadata.uid)throw Error('Resource slot holder changed');
 // If an earlier pause failed before adding its owner marker, no StatefulSet was stopped.
 if(!s.paused&&!sts.metadata.annotations?.[ownerKey]&&sts.spec.replicas===s.replicas&&sts.status.readyReplicas===s.replicas&&sts.status.observedGeneration>=sts.metadata.generation){markRestored(s);return;}
 validateRestore(sts,s);
 if(sts.spec.replicas!==s.replicas)kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.uid},{op:'test',path:'/metadata/annotations/'+escape(ownerKey),value:holder},{op:'replace',path:'/spec/replicas',value:s.replicas}])]);
 for(let i=0;i<300;i++){
  sts=get(['-n','sonarqube','get','statefulset','sonarqube-sonarqube']);validateRestore(sts,s);
  if(sts.status.readyReplicas===s.replicas&&sts.status.observedGeneration>=sts.metadata.generation){
   const svc=get(['-n','sonarqube','get','service','sonarqube-sonarqube']);const r=await fetch('http'+'://'+svc.spec.clusterIP+':9000/api/system/status',{signal:AbortSignal.timeout(10000)});if(!r.ok||(await r.json()).status!=='UP'){await sleep();continue;}
   if(sts.metadata.annotations?.[ownerKey]===holder)kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.uid},{op:'test',path:'/metadata/annotations/'+escape(ownerKey),value:holder},{op:'remove',path:'/metadata/annotations/'+escape(ownerKey)}])]);
   s.restoredAt=new Date().toISOString();s.restoredHttp='UP';markRestored(s);console.log('Original Sonar replica Ready and HTTP UP; hold dispatch quiet until Lease release');return;
  }await sleep();
 }
 throw Error('Sonar restoration not proven; preserve outer Lease and Jenkins quiet state');
}
if(process.argv[1]===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
