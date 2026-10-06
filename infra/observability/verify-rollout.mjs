import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

// Classifications describe observed release blockers, not an unproven infrastructure RCA.
export function assess(snapshot, image, revision, now = Date.now()) {
 const {deployment:d, pods, nodes, leases, events, argo} = snapshot;
 if (d.spec.template.spec.containers.find(c=>c.name==='petclinic')?.image !== image)
  return {fatal:'RELEASE_SUPERSEDED: live desired image changed', blockers:[]};
 const active=pods.filter(p=>!p.metadata.deletionTimestamp);
 const blockers=active.map(p=>{
  const c=p.status.containerStatuses?.find(c=>c.name==='petclinic');
  const node=nodes.find(n=>n.metadata.name===p.spec.nodeName);
  const ready=node?.status.conditions.find(c=>c.type==='Ready');
  const lease=leases.find(l=>l.metadata.name===p.spec.nodeName);
  const leaseAge=lease?.spec.renewTime ? Math.max(0,(now-Date.parse(lease.spec.renewTime))/1000) : null;
  const related=events.filter(e=>e.involvedObject?.uid===p.metadata.uid);
  const reasons=[p.status.phase,c?.state.waiting?.reason,...related.filter(e=>e.type==='Warning').map(e=>e.reason)].filter(Boolean);
  const mount=related.some(e=>e.reason==='FailedMount' && /failed to sync (configmap|secret) cache/i.test(e.message));
  const readyPod=p.status.conditions?.some(c=>c.type==='Ready'&&c.status==='True');
  const fatalImage=['ErrImagePull','ImagePullBackOff','InvalidImageName'].includes(c?.state.waiting?.reason) && related.some(e=>/manifest unknown|no matching manifest|invalid reference format|unauthorized: authentication required/i.test(e.message));
  return {pod:p.metadata.name,uid:p.metadata.uid,node:p.spec.nodeName??'unscheduled',reasons,
   nodeReady:ready?.status??'unknown',leaseAgeSeconds:leaseAge,ready:!!readyPod,
   nodeSyncBlocked:!!(mount && ready && ready.status!=='True' && leaseAge!==null && leaseAge>40),
   fatal:!!(c?.state.waiting?.reason==='InvalidImageName'||fatalImage||
    (c?.state.waiting?.reason==='CrashLoopBackOff' && c.restartCount>=3))};
 }).filter(p=>!p.ready);
 const fatal=blockers.find(p=>p.fatal);
 const desired=d.spec.replicas??1, status=d.status;
 const nodesHealthy=active.every(p=>{
  const node=nodes.find(n=>n.metadata.name===p.spec.nodeName),lease=leases.find(l=>l.metadata.name===p.spec.nodeName);
  return node?.status.conditions.some(c=>c.type==='Ready'&&c.status==='True') &&
   !node.status.conditions.some(c=>['MemoryPressure','DiskPressure','PIDPressure','NetworkUnavailable'].includes(c.type)&&c.status!=='False') &&
   lease?.spec.renewTime && now-Date.parse(lease.spec.renewTime)<=40000;
 });
 const complete=nodesHealthy && status.observedGeneration>=d.metadata.generation && status.replicas===desired &&
  status.updatedReplicas===desired && status.readyReplicas===desired && status.availableReplicas===desired &&
  active.length===desired && active.every(p=>p.spec.containers.find(c=>c.name==='petclinic')?.image===image &&
   p.status.conditions?.some(c=>c.type==='Ready'&&c.status==='True')) &&
  argo.status.sync.status==='Synced' && argo.status.health.status==='Healthy' && argo.status.sync.revision===revision;
 return {complete,blockers,fatal:fatal?`PERMANENT_POD_FAILURE: ${fatal.pod} on ${fatal.node}`:null};
}

export async function verify(image,revision,{timeoutMs=600000,pollMs=10000,output='target/platform/rollout-diagnostics.json'}={}) {
 const started=Date.now(), history=[], blockedSince=new Map();let last, failure;
 function kubectl(args,json=true){
  const remaining=Math.max(1,Math.min(6000,started+timeoutMs-Date.now()));
  const r=spawnSync('kubectl',['--request-timeout=5s',...args,...(json?['-o','json']:[])],{encoding:'utf8',timeout:remaining,maxBuffer:4*1024*1024});
  if(r.status!==0)throw Error(`kubectl ${args.join(' ')}: ${r.error?.message||r.stderr.trim()}`);
  return json?JSON.parse(r.stdout):r.stdout;
 }
 const save=()=>{fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify({image,revision,started,finished:Date.now(),failure,samples:history},null,2));};
 try {
  if(!image||!revision)throw Error('Expected immutable image and Git revision are required');
  while(Date.now()-started<timeoutMs){
   try {
    const resources=kubectl(['-n','petclinic','get','deployment,pods,events']).items;
    const snapshot={deployment:resources.find(x=>x.kind==='Deployment'&&x.metadata.name==='petclinic'),
     pods:resources.filter(x=>x.kind==='Pod'&&x.metadata.labels?.app==='petclinic'),events:resources.filter(x=>x.kind==='Event'),
     nodes:kubectl(['get','nodes']).items,leases:kubectl(['-n','kube-node-lease','get','leases']).items,
     argo:kubectl(['-n','argocd','get','application','petclinic'])};
    last=assess(snapshot,image,revision);
    // Persist metadata/status only. Never archive Pod environments, Secret values or business data.
    history.push({time:Date.now(),assessment:last,deployment:snapshot.deployment.status,
     nodes:snapshot.nodes.map(n=>({name:n.metadata.name,conditions:n.status.conditions,capacity:n.status.capacity,allocatable:n.status.allocatable})),
     leases:snapshot.leases.map(l=>({node:l.metadata.name,renewTime:l.spec.renewTime})),
     events:snapshot.events.map(e=>({pod:e.involvedObject?.name,uid:e.involvedObject?.uid,reason:e.reason,message:e.message,count:e.count,lastTimestamp:e.lastTimestamp}))});
   }catch(error){history.push({time:Date.now(),apiError:error.message});console.error(`ROLLOUT_API_ERROR: ${error.message}`);save();await new Promise(r=>setTimeout(r,Math.min(pollMs,Math.max(0,timeoutMs-(Date.now()-started)))));continue;}
   console.log(`ROLLOUT_CHECK ${JSON.stringify(last)}`);save();
   if(last.fatal)throw Error(last.fatal);
   const currentBlocked=new Set();
   for(const p of last.blockers.filter(p=>p.nodeSyncBlocked)){
    currentBlocked.add(p.uid);if(!blockedSince.has(p.uid))blockedSince.set(p.uid,Date.now());
    if(Date.now()-blockedSince.get(p.uid)>=90000)throw Error(`NODE_API_SYNC_BLOCKED: ${p.pod} on ${p.node}; FailedMount + non-Ready node + stale Lease persisted 90s. Infrastructure root cause not yet proven; see diagnostics.`);
   }
   for(const uid of blockedSince.keys())if(!currentBlocked.has(uid))blockedSince.delete(uid);
   if(last.complete){console.log('ROLLOUT_VERIFIED: exact Git revision, immutable image, all desired replicas Ready/Available');return;}
   await new Promise(r=>setTimeout(r,Math.min(pollMs,Math.max(0,timeoutMs-(Date.now()-started)))));
  }
  throw Error('ROLLOUT_TIMEOUT: release did not converge within the existing 600-second budget');
 }catch(error){
  failure=error.message;save();console.error(failure);
  const cmds=[['get','nodes','-o','wide'],['-n','petclinic','get','pods','-o','wide'],['-n','petclinic','describe','deployment','petclinic'],['-n','petclinic','get','events','--sort-by=.lastTimestamp']];
  for(const p of last?.blockers??[]){cmds.push(['-n','petclinic','describe','pod',p.pod]);if(p.node!=='unscheduled')cmds.push(['describe','node',p.node],['-n','kube-node-lease','get','lease',p.node,'-o','yaml']);}
  for(const args of cmds){const r=spawnSync('kubectl',['--request-timeout=5s',...args],{encoding:'utf8',timeout:6000,maxBuffer:1024*1024});console.error(`DIAGNOSTIC kubectl ${args.join(' ')}\n${r.stdout||r.stderr||r.error?.message}`);}
  throw error;
 }finally{save();}
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href)
 verify(process.env.K8S_IMAGE,process.argv[2]).catch(()=>{process.exitCode=1;});
