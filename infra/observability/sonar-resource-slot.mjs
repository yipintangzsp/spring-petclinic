// Borrow the existing CI Lease; never acquire a second lock or remove Sonar data.
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const ns='data-infra',leaseName='platform-heavy',ownerKey='petclinic.devops.local/analysis-holder',stateKey='petclinic.devops.local/paused-sonar';
const file='.devsecops/sonar-resource-slot.json';
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
async function main(){
 const mode=process.argv[2],holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${process.env.BUILD_NUMBER}`;
 if(!['pause','restore','resume'].includes(mode))throw Error('Use pause/restore/resume');
 if(mode==='resume'){
  if(!fs.existsSync(file))return;
  const s=JSON.parse(fs.readFileSync(file));if(!s.restored||s.holder!==holder)throw Error('Restoration not proven; retain quiet state');
  if(kube(['-n',ns,'get','lease',leaseName,'--ignore-not-found','-o','json']).trim())throw Error('Release owned Lease before resuming Jenkins');
  if(!s.originalQuiet)jenkins('/cancelQuietDown','POST');
  s.jenkinsQuietRestored=true;save(s);console.log('Original Jenkins dispatch state restored');return;
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
  const gate=JSON.parse(fs.readFileSync('target/platform/sonar-quality.json'));if(gate.gate?.status!=='OK')throw Error('Completed original Sonar quality gate required');
  const host=process.env.SONAR_HOST_URL;if(new URL(host).hostname!=='sonarqube-sonarqube.sonarqube.svc.cluster.local'||!process.env.SONAR_TOKEN)throw Error('Existing scoped Sonar credential and endpoint required');
  const report=Object.fromEntries(fs.readFileSync('target/sonar/report-task.txt','utf8').trim().split(/\r?\n/).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)];}));
  if(report.projectKey!=='petclinic'||!report.ceTaskId)throw Error('Original current Maven analysis task required');
  const q=await fetch(host+'/api/ce/task?id='+encodeURIComponent(report.ceTaskId),{headers:{Authorization:'Bearer '+process.env.SONAR_TOKEN},signal:AbortSignal.timeout(10000)});if(!q.ok)throw Error('Cannot verify submitted analysis task HTTP '+q.status);const ce=await q.json();
  if(ce.task?.id!==report.ceTaskId||ce.task.status!=='SUCCESS'||ce.task.componentKey!=='petclinic')throw Error('Submitted project analysis is not complete');
  const secret=get(['-n','sonarqube','get','secret','sonarqube-sonarqube-monitoring-passcode']);const pass=Buffer.from(secret.data.SONAR_WEB_SYSTEMPASSCODE,'base64').toString();
  const r=await fetch(host+'/api/monitoring/metrics',{headers:{'X-Sonar-Passcode':pass},signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('Existing monitoring identity cannot verify pending queue');
  const pending=(await r.text()).match(/^sonarqube_compute_engine_pending_tasks_total\s+([\d.]+)$/m);if(!pending||Number(pending[1])!==0)throw Error('Global pending queue is not empty');
  const j=jenkins(statePath);if(otherBuilds(j.jobs,process.env.JOB_NAME,process.env.BUILD_NUMBER))throw Error('Another Jenkins build is active');
  s.originalQuiet=j.quietingDown;s.queueProof={submittedTask:report.ceTaskId,submittedTaskStatus:'SUCCESS',globalPending:0,scope:'Known platform scans serialized through Jenkins; unregistered external in-progress scans are not globally proven'};s.paused=false;s.restored=false;s.startedAt=new Date().toISOString();save(s);
  kube(['-n',ns,'patch','lease',leaseName,'--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.leaseUid},{op:'add',path:'/metadata/annotations',value:{...(lease.metadata.annotations??{}),[stateKey]:JSON.stringify(s)}}])]);
  if(!j.quietingDown)jenkins('/quietDown?block=false','POST');
  const quiet=jenkins(statePath);if(!quiet.quietingDown||otherBuilds(quiet.jobs,process.env.JOB_NAME,process.env.BUILD_NUMBER))throw Error('Exclusive known scanner dispatch not confirmed');
  const patch=[{op:'test',path:'/metadata/uid',value:s.uid},{op:'test',path:'/metadata/resourceVersion',value:sts.metadata.resourceVersion}];
  if(!sts.metadata.annotations)patch.push({op:'add',path:'/metadata/annotations',value:{}});
  patch.push({op:'add',path:'/metadata/annotations/'+escape(ownerKey),value:holder},{op:'replace',path:'/spec/replicas',value:0});
  kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify(patch)]);s.paused=true;save(s);
  for(let i=0;i<60;i++){const raw=kube(['-n','sonarqube','get','pod','sonarqube-sonarqube-0','--ignore-not-found','-o','json']);if(!raw.trim()){s.stoppedAt=new Date().toISOString();save(s);console.log('Idle Sonar memory released after completed quality gate; PVC preserved');return;}if(JSON.parse(raw).metadata.uid!==s.originalPodUid)throw Error('Unexpected replacement Sonar pod during pause');await sleep();}
  throw Error('Sonar graceful stop not confirmed');
 }
 const recorded=lease.metadata.annotations?.[stateKey];
 if(!recorded&&!fs.existsSync(file)){console.log('No scanner resource slot to restore');return;}
 let s=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):JSON.parse(recorded);
 if(s.holder!==holder||s.leaseUid!==lease.metadata.uid)throw Error('Resource slot holder changed');
 // If an earlier pause failed before adding its owner marker, no StatefulSet was stopped.
 if(!s.paused&&!sts.metadata.annotations?.[ownerKey]&&sts.spec.replicas===s.replicas&&sts.status.readyReplicas===s.replicas&&sts.status.observedGeneration>=sts.metadata.generation){s.restored=true;save(s);return;}
 validateRestore(sts,s);
 if(sts.spec.replicas!==s.replicas)kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.uid},{op:'test',path:'/metadata/annotations/'+escape(ownerKey),value:holder},{op:'replace',path:'/spec/replicas',value:s.replicas}])]);
 for(let i=0;i<300;i++){
  sts=get(['-n','sonarqube','get','statefulset','sonarqube-sonarqube']);validateRestore(sts,s);
  if(sts.status.readyReplicas===s.replicas&&sts.status.observedGeneration>=sts.metadata.generation){
   const svc=get(['-n','sonarqube','get','service','sonarqube-sonarqube']);const r=await fetch('http'+'://'+svc.spec.clusterIP+':9000/api/system/status',{signal:AbortSignal.timeout(10000)});if(!r.ok||(await r.json()).status!=='UP'){await sleep();continue;}
   if(sts.metadata.annotations?.[ownerKey]===holder)kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:s.uid},{op:'test',path:'/metadata/annotations/'+escape(ownerKey),value:holder},{op:'remove',path:'/metadata/annotations/'+escape(ownerKey)}])]);
   s.restored=true;s.restoredAt=new Date().toISOString();s.restoredHttp='UP';save(s);console.log('Original Sonar replica Ready and HTTP UP; hold dispatch quiet until Lease release');return;
  }await sleep();
 }
 throw Error('Sonar restoration not proven; preserve outer Lease and Jenkins quiet state');
}
if(process.argv[1]===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
