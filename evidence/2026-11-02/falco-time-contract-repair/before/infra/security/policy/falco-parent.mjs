import fs from 'node:fs';import crypto from 'node:crypto';
import {runtimeWindow,persistentRuntime} from '../runtime/event-policy.mjs';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from '../runtime/health-contract.mjs';
export function falcoParent(raw){
 const binding=JSON.parse(fs.readFileSync(new URL('./versions/falco-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(binding.sourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../'+p.replace('infra/security/',''),import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen Falco source changed');
 if(!raw?.observations||!raw?.configuration)return {decision:null,status:'NOT_CONFIGURED',reason:'Complete Falco observations absent'};
 const o=raw.observations,cfg=raw.configuration,read=p=>{const x=o.files[p];if(!x||x.error)throw Error('file read failed: '+p);return x.value;};
 const run=(x)=>{if(!x||x.status!==0)throw Error('command failed');return x.stdout;};let assessment=null,historicalWarning=null,baseline;
 try{
  if(!o.leaseOwned)throw Error('outer Lease required');
  const proof=JSON.parse(read('proof')),lock=JSON.parse(read('lock'));
  if(!['baseline','check'].includes(raw.mode))throw Error('Use baseline/check');
  if(proof.rulesetLabel!==lock.rulesetLabel||!proof.cleanup.removed)throw Error('Matching isolated proof required');
  if(read('manifestHash')!==lock.manifestSha256)throw Error('manifest mismatch');
  const ds=JSON.parse(run(o.ds));if(!Number.isInteger(ds.status.desiredNumberScheduled)||ds.status.desiredNumberScheduled<1||ds.status.numberReady!==ds.status.desiredNumberScheduled)throw Error('DaemonSet mismatch');
  const pods=JSON.parse(run(o.sensorPods)).items.filter(p=>!p.metadata.deletionTimestamp);
  if(pods.length!==1||pods[0].spec.nodeName!=='devops'||!pods[0].spec.containers[0].image.endsWith(lock.arm64ManifestDigest))throw Error('coverage mismatch');
  const pod=pods[0];if(pod.metadata.labels['petclinic.devops.local/runtime-ruleset']!==lock.rulesetLabel)throw Error('ruleset mismatch');
  const container=pod.status.containerStatuses.find(x=>x.name==='falco'),node=JSON.parse(run(o.node));
  const current={podUid:pod.metadata.uid,nodeBootId:node.status.nodeInfo.bootID,containerId:container?.containerID,runningSince:container?.state?.running?.startedAt,image:pod.spec.containers[0].image,restarts:container?.restartCount,ready:container?.ready,priorExit:container?.lastState?.terminated};
  const source=read('source').trim();
  if(raw.mode==='baseline'){
   historicalWarning=validatePriorExit(current);
   if(!current.nodeBootId||!current.containerId||!Number.isFinite(Date.parse(current.runningSince))||raw.now-Date.parse(current.runningSince)<300000)throw Error('stable identity required');
   baseline={...current,source,build:String(raw.build),capturedAt:new Date(raw.now).toISOString()};
  }else{
   if(!o.baselineExists)throw Error('baseline missing');baseline=JSON.parse(read('baseline'));
   if(baseline.source!==source||baseline.build!==String(raw.build))throw Error('foreign baseline');validateRuntimeContinuity(current,baseline);
  }
  const diagnostics=driverDiagnostics(run(o.diagnosticLog));
  const sample=i=>{
   const end=raw.now+i*16000,start=end-15000,live=run(o.samples[i].log),events=[];let malformed=0;
   for(const line of live.split('\n')){try{const event=JSON.parse(line);if(event.rule)events.push(event);}catch{if(line.trim().startsWith('{'))malformed++;}}
   const map={};for(const p of JSON.parse(run(o.samples[i].workloads)).items)for(const c of p.status.containerStatuses??[])map[`petclinic/${p.metadata.name}/${c.name}`]={podUid:p.metadata.uid,containerId:c.containerID,node:p.spec.nodeName,ready:c.ready,startedAt:c.state?.running?.startedAt};
   return {...driverDiagnostics(live),at:new Date(end).toISOString(),malformedJsonLines:malformed,window:runtimeWindow(events,map,start,end)};
  };
  const liveChecks=[sample(0)];assessment={status:'success',blocking:[],first:liveChecks[0].window,criteria:'Point-in-time local Falco gate, not continuous or cloud coverage'};
  if(liveChecks[0].fatalDriverLines)throw Error('current driver fatal');
  if(liveChecks[0].window.candidates.some(x=>x.count>=2)){
   liveChecks.push(sample(1));assessment=persistentRuntime(liveChecks[0].window,liveChecks[1].window);
   if(liveChecks[1].fatalDriverLines||assessment.blocking.length)throw Error('current fatal or persistent confirmed behavior');
  }
  if(o.health.error||!o.health.ok)throw Error('actual health failed');
  if(!o.mkdirSucceeded)throw Error('output directory failed');
  if(raw.mode==='baseline'&&!o.baselineWriteSucceeded)throw Error('baseline write failed');
  // The original constructs validationEvidence while serializing the success report.
  proof.cases.map(x=>({case:x.case,status:x.status}));
  if(!o.reportWriteSucceeded)throw Error('report write failed');
  return {decision:'PASS',status:'PASS',sensorHealth:'verified-for-frozen-window',historicalWarning,diagnostics,liveChecks,runtimeAssessment:assessment,baseline,rawEvidence:structuredClone(raw)};
 }catch(error){return {decision:'FAIL',status:'FAIL',reason:error.message,runtimeAssessment:assessment,rawEvidence:structuredClone(raw)};}
}
