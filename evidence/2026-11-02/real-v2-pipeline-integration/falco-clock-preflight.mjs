// Controlled compatibility PRECHECK, not live events or a real production incident.
// Execute the existing complete production Gate body with inert IO and observed
// clock progression. Never invoke kubectl, fetch, a scanner, signing or publishing.
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {runtimeWindow,persistentRuntime} from '../../../infra/security/runtime/event-policy.mjs';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from '../../../infra/security/runtime/health-contract.mjs';
import {evaluate} from '../../../infra/security/policy/engine.mjs';

const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url);
const read=p=>JSON.parse(fs.readFileSync(new URL(p,root)));
const production=fs.readFileSync(new URL('infra/security/runtime/health.mjs',root),'utf8');
const body=production.replace(/^import .*;\s*$/gm,'');
const lock=read('infra/security/runtime/lock.json'),proof=read('infra/security/runtime/isolated-sensor-proof.json');
const now=Date.parse('2026-11-02T00:00:00Z'),containerId='a'.repeat(64);
const response=value=>({status:0,stdout:typeof value==='string'?value:JSON.stringify(value),stderr:''});
const file=value=>({value:typeof value==='string'?value:JSON.stringify(value)});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');

function fixture(mode,delay){
 const current={podUid:'controlled-sensor-uid',nodeBootId:'controlled-boot',containerId:'containerd://'+'b'.repeat(64),runningSince:new Date(now-3600000).toISOString(),image:'registry.invalid/sensor@'+lock.arm64ManifestDigest,restarts:0,ready:true};
 const pod={metadata:{uid:current.podUid,name:'controlled-sensor',labels:{'petclinic.devops.local/runtime-ruleset':lock.rulesetLabel}},spec:{nodeName:'devops',containers:[{name:'falco',image:current.image}]},status:{podIP:'127.0.0.1',containerStatuses:[{name:'falco',containerID:current.containerId,restartCount:0,ready:true,state:{running:{startedAt:current.runningSince}},lastState:{}}]}};
 const workload={items:[{metadata:{name:'controlled-app',uid:'controlled-app-uid'},spec:{nodeName:'devops'},status:{containerStatuses:[{name:'app',containerID:'containerd://'+containerId,ready:true,state:{running:{startedAt:new Date(now-3600000).toISOString()}}}]}}]};
 const events=end=>[-1000,-500].map(offset=>({time:new Date(end+offset).toISOString(),rule:'Platform Runtime Sensitive Write',priority:'Warning',output_fields:{'k8s.ns.name':'petclinic','k8s.pod.name':'controlled-app','container.name':'app','container.id':containerId.slice(0,12),'evt.res':'SUCCESS','evt.type':'openat','evt.arg.name':'/etc/ld.so.preload','proc.name':'cp'}}));
 const actualSampleEnds=[now,now+16000+delay];
 return {classification:'CONTROLLED_REPLAY_NOT_LIVE_RUNTIME',mode,now,build:'isolated-clock-case',configuration:{},
  capturedSampleEnds:actualSampleEnds,observations:{leaseOwned:true,files:{proof:file(proof),lock:file(lock),manifestHash:file(lock.manifestSha256),source:file('c'.repeat(40)),baseline:file({...current,source:'c'.repeat(40),build:'isolated-clock-case',capturedAt:new Date(now-60000).toISOString()})},baselineExists:true,
  ds:response({status:{desiredNumberScheduled:1,numberReady:1}}),sensorPods:response({items:[pod]}),node:response({status:{nodeInfo:{bootID:current.nodeBootId}}}),diagnosticLog:response(''),
  samples:actualSampleEnds.map(end=>({log:response(events(end).map(e=>JSON.stringify(e)).join('\n')),workloads:response(workload)})),
  health:{ok:true,status:200},mkdirSucceeded:true,baselineWriteSucceeded:true,reportWriteSucceeded:true}};
}
async function originalGate(raw,delay){
 let clock=raw.now,live=0,workloads=0;const writes={},clockReads=[],waits=[];
 class ObservedDate extends Date{constructor(...args){super(...(args.length?args:[clock]));}static now(){clockReads.push(clock);return clock;}}
 const o=raw.observations;
 const fsObserved={readFileSync:p=>{
  const key=p.endsWith('isolated-sensor-proof.json')?'proof':p.endsWith('lock.json')?'lock':p==='.git-sha'?'source':p.endsWith('runtime-baseline.json')?'baseline':p.endsWith('falco.json')?'manifestHash':null;
  if(!key||!o.files[key])throw Error('unobserved read');return key==='manifestHash'?{observedHash:o.files[key].value}:o.files[key].value;
 },existsSync:()=>o.baselineExists,mkdirSync:()=>{},writeFileSync:(p,v)=>{writes[p]=JSON.parse(v);}};
 const spawnSync=(_bin,args)=>{
  if(args.includes('ds'))return o.ds;if(args.includes('node'))return o.node;
  if(args.includes('logs'))return args.includes('--tail=500')?o.diagnosticLog:o.samples[live++].log;
  if(args.includes('petclinic')){const value=o.samples[workloads++].workloads;if(workloads===1)clock+=delay;return value;}
  return o.sensorPods;
 };
 const context={fs:fsObserved,runtimeWindow,persistentRuntime,validatePriorExit,validateRuntimeContinuity,driverDiagnostics,
  crypto:{createHash:()=>({update:v=>({digest:()=>v.observedHash})})},spawnSync,requireLease:()=>{},process:{argv:['node','health',raw.mode],env:{BUILD_NUMBER:raw.build}},
  Date:ObservedDate,console:{warn:()=>{}},setTimeout:(fn,ms)=>{waits.push(ms);clock+=ms;fn();},fetch:async()=>o.health,AbortSignal};
 let decision='PASS',reason=null;
 try{await vm.runInNewContext('(async()=>{'+body+'})()',context);}catch(error){decision='FAIL';reason=error.message;}
 const actualEnds=clockReads.slice(-2);
 if(!isDeepStrictEqual(actualEnds,raw.capturedSampleEnds))throw Error('Clock observation mismatch; invalid compatibility probe');
 return {decision,reason,clockReads,actualSampleEnds:actualEnds,requestedWaits:waits,report:writes['.devsecops/runtime-health.json']};
}
const records=[];
for(const mode of ['baseline','check'])for(const delay of [0,2000]){
 const raw=fixture(mode,delay),before=JSON.stringify(raw),old=await originalGate(raw,delay);
 const standard=evaluate({component:mode==='baseline'?'falco-baseline':'falco-final',status:'success',raw});
 const record={classification:raw.classification,mode,firstSampleProcessingDelayMs:delay,productionWaitMs:16000,actualSampleEnds:old.actualSampleEnds.map(x=>new Date(x).toISOString()),adapterSampleEnds:[raw.now,raw.now+16000].map(x=>new Date(x).toISOString()),oldDecision:old.decision,standardDecision:standard.decision,oldReason:old.reason,standardReason:standard.reason??null,
  match:old.decision===standard.decision,rawPreserved:before===JSON.stringify(raw),sourceSha256:sha(production),adapterSha256:sha(fs.readFileSync(new URL('infra/security/policy/falco-parent.mjs',root))),rawSha256:sha(before),
  originalRuntimeAssessment:old.report?.runtimeAssessment,policyRuntimeAssessment:standard.runtimeAssessment,policyWindow:standard.liveChecks?.map(x=>x.window),existingProductionWrites:false};
 fs.writeFileSync(new URL('clock-'+mode+'-'+delay+'ms-input.json',out),JSON.stringify(raw,null,2)+'\n');records.push(record);
}
const evidence={classification:'CONTROLLED_ORIGINAL_PRODUCTION_BODY_REPLAY_NOT_LIVE_PIPELINE',records,
 cleanClockControlsMatch:records.filter(r=>r.firstSampleProcessingDelayMs===0).every(r=>r.match),
 delayedClockCasesDrift:records.filter(r=>r.firstSampleProcessingDelayMs>0).every(r=>!r.match),
 sourceAndAdapterModified:false,
 blocker:'falco-parent uses raw.now+i*16000 for sample ends. Production waits 16000 only AFTER first sample IO; the actual next Date.now includes IO/scheduling latency. Complete passive facts cannot be represented faithfully for both windows by the single raw.now field.',
 requiredAction:'STOP integration. Correct the frozen adapter to consume actual observed per-sample clock bounds only in a separately reviewed compatibility revalidation; do not change production timing, drop events, shift timestamps, or mark this source skipped.'};
fs.writeFileSync(new URL('falco-clock-preflight.json',out),JSON.stringify(evidence,null,2)+'\n');
console.log(JSON.stringify({controls:records.filter(x=>x.match).length,drifts:records.filter(x=>!x.match).map(({mode,oldDecision,standardDecision})=>({mode,oldDecision,standardDecision})),sourceModified:false,productionCalls:0}));
if(evidence.delayedClockCasesDrift)process.exitCode=2;
