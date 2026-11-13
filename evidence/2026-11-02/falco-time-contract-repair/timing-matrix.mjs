// Controlled whole-Gate replay. No network, shell, kubectl or real sensor calls.
// Raw timing is captured from the original production body BEFORE Policy runs.
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {runtimeWindow,persistentRuntime} from '../../../infra/security/runtime/event-policy.mjs';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from '../../../infra/security/runtime/health-contract.mjs';
import {evaluate} from '../../../infra/security/policy/engine.mjs';

const phase=process.argv[2];assert.ok(['before','after'].includes(phase));
const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const read=p=>JSON.parse(fs.readFileSync(new URL(p,root)));
const source=fs.readFileSync(new URL('infra/security/runtime/health.mjs',root),'utf8'),body=source.replace(/^import .*;\s*$/gm,'');
const beforeIdentity=JSON.parse(fs.readFileSync(new URL('FALCO_BEFORE_IDENTITY.json',out)));
assert.equal(sha(source),beforeIdentity.productionBaselineGate);
const lock=read('infra/security/runtime/lock.json'),proof=read('infra/security/runtime/isolated-sensor-proof.json');
const now=Date.parse('2026-11-02T00:00:00Z'),cid='a'.repeat(64);
const response=x=>({status:0,stdout:typeof x==='string'?x:JSON.stringify(x),stderr:''});
const file=x=>({value:typeof x==='string'?x:JSON.stringify(x)});
const specs=[];
for(const ms of [0,1,250,999,1000,2000,14999])specs.push({id:'first-log-io-'+ms,firstLogMs:ms});
specs.push({id:'original-drift-2s',firstWorkloadMs:2000,original:true});
specs.push({id:'first-workload-io-2000',firstWorkloadMs:2000});
for(const ms of [1000,2000])specs.push({id:'before-first-sample-io-'+ms,diagnosticMs:ms});
for(const ms of [250,2000,14999])specs.push({id:'second-log-io-'+ms,secondLogMs:ms});
for(const ms of [1,1000,2000])specs.push({id:'timer-overshoot-'+ms,waitExtraMs:ms});
for(const sample of [0,1])for(const edge of ['lower-exact','upper-exact','lower-before','lower-after','upper-before','upper-after'])specs.push({id:'sample-'+sample+'-'+edge,boundary:{sample,edge}});
for(const fail of ['diagnostic','first-log','first-workload','second-log','second-workload'])specs.push({id:fail+'-timeout-no-retry',fail});
specs.push({id:'clock-adjustment-overlapping-windows',clockAdjustmentMs:-5000});
for(const edge of ['before-upper-nanoseconds','at-upper-nanoseconds'])specs.push({id:edge,boundary:{sample:1,edge}});

function clocks(spec){const first=now+(spec.diagnosticMs??0);return [first,first+(spec.firstLogMs??0)+(spec.firstWorkloadMs??0)+16000+(spec.waitExtraMs??0)+(spec.clockAdjustmentMs??0)];}
function fixture(mode,spec){
 if(spec.original)return read('evidence/2026-11-02/real-v2-pipeline-integration/clock-'+mode+'-2000ms-input.json');
 const current={podUid:'controlled-sensor-uid',nodeBootId:'controlled-boot',containerId:'containerd://'+'b'.repeat(64),runningSince:new Date(now-3600000).toISOString(),image:'registry.invalid/sensor@'+lock.arm64ManifestDigest,restarts:0,ready:true};
 const pod={metadata:{uid:current.podUid,name:'controlled-sensor',labels:{'petclinic.devops.local/runtime-ruleset':lock.rulesetLabel}},spec:{nodeName:'devops',containers:[{name:'falco',image:current.image}]},status:{podIP:'127.0.0.1',containerStatuses:[{name:'falco',containerID:current.containerId,restartCount:0,ready:true,state:{running:{startedAt:current.runningSince}},lastState:{}}]}};
 const workloads={items:[{metadata:{name:'controlled-app',uid:'controlled-app-uid'},spec:{nodeName:'devops'},status:{containerStatuses:[{name:'app',containerID:'containerd://'+cid,ready:true,state:{running:{startedAt:new Date(now-3600000).toISOString()}}}]}}]};
 const events=(end,index)=>[-8000,-500].map((offset,eventIndex)=>{
  let time=new Date(end+offset).toISOString();
  if(spec.boundary?.sample===index&&eventIndex===1){
   const delta={'lower-exact':-15000,'upper-exact':0,'lower-before':-15001,'lower-after':-14999,'upper-before':-1,'upper-after':1}[spec.boundary.edge];
   if(delta!==undefined)time=new Date(end+delta).toISOString();
   if(spec.boundary.edge==='before-upper-nanoseconds')time=new Date(end-1).toISOString().replace('.999Z','.999999999Z');
   if(spec.boundary.edge==='at-upper-nanoseconds')time=new Date(end).toISOString().replace('.000Z','.000000001Z');
  }
  return {time,rule:'Platform Runtime Sensitive Write',priority:'Warning',output_fields:{'k8s.ns.name':'petclinic','k8s.pod.name':'controlled-app','container.name':'app','container.id':cid.slice(0,12),'evt.res':'SUCCESS','evt.type':'openat','evt.arg.name':'/etc/ld.so.preload','proc.name':'cp'}};
 });
 return {classification:'CONTROLLED_CAPTURED_TIMING_REPLAY_NOT_LIVE_SENSOR',mode,now,build:'controlled-clock',configuration:{},observations:{leaseOwned:true,
 files:{proof:file(proof),lock:file(lock),manifestHash:file(lock.manifestSha256),source:file('c'.repeat(40)),baseline:file({...current,source:'c'.repeat(40),build:'controlled-clock',capturedAt:new Date(now-60000).toISOString()})},baselineExists:true,
 ds:response({status:{desiredNumberScheduled:1,numberReady:1}}),sensorPods:response({items:[pod]}),node:response({status:{nodeInfo:{bootID:current.nodeBootId}}}),diagnosticLog:response(''),
 samples:clocks(spec).map((end,index)=>({log:response(events(end,index).map(x=>JSON.stringify(x)).join('\n')),workloads:response(workloads)})),
 health:{ok:true,status:200},mkdirSucceeded:true,baselineWriteSucceeded:true,reportWriteSucceeded:true}};
}
async function original(raw,spec){
 let clock=raw.now,live=0,workloads=0;const writes={},trace=[],timing={clockSource:'Date.now',observations:[],wait:null,retries:0},o=raw.observations;
 class ObservedDate extends Date{constructor(...args){super(...(args.length?args:[clock]));}static now(){trace.push({kind:'Date.now',value:clock});return clock;}}
 const fakeFs={readFileSync:p=>{const key=p.endsWith('isolated-sensor-proof.json')?'proof':p.endsWith('lock.json')?'lock':p==='.git-sha'?'source':p.endsWith('runtime-baseline.json')?'baseline':p.endsWith('falco.json')?'manifestHash':null;if(!key)throw Error('unobserved read');return key==='manifestHash'?{observedHash:o.files[key].value}:o.files[key].value;},existsSync:()=>o.baselineExists,mkdirSync:()=>{},writeFileSync:(p,v)=>{writes[p]=JSON.parse(v);}};
 const cmd=(key,result,duration=0)=>{
  const start=clock,failed=spec.fail===key;clock+=failed?20000:duration;
  const r=failed?{status:null,stdout:'',stderr:'controlled ETIMEDOUT',error:{code:'ETIMEDOUT'}}:result;
  trace.push({kind:'command',key,startedAtMs:start,completedAtMs:clock,exitStatus:r.status,error:r.error??null,retries:0});return r;
 };
 const spawnSync=(_bin,args)=>{
  if(args.includes('ds'))return cmd('ds',o.ds);if(args.includes('node'))return cmd('node',o.node);
  if(args.includes('logs')){
   if(args.includes('--tail=500')){const r=cmd('diagnostic',o.diagnosticLog,spec.diagnosticMs??0);o.diagnosticLog=r;return r;}
   const i=live++,sample=o.samples[i],startIso=args.find(a=>a.startsWith('--since-time=')).split('=')[1];
   // Clock was sampled by the ORIGINAL body immediately before this command.
   sample.windowEndMs=clock;
   const observation={index:i,startedAtMs:clock,windowStartMs:Date.parse(startIso),windowEndMs:clock,querySince:startIso,completedAtMs:null};timing.observations.push(observation);
   assert.equal(observation.windowStartMs,observation.windowEndMs-15000);
   const r=cmd(i===0?'first-log':'second-log',sample.log,i===0?spec.firstLogMs??0:spec.secondLogMs??0);sample.log=r;
   if(r.status!==0)observation.completedAtMs=clock;
   return r;
  }
  if(args.includes('petclinic')){
   const i=workloads++,sample=o.samples[i],r=cmd(i===0?'first-workload':'second-workload',sample.workloads,i===0?spec.firstWorkloadMs??0:0);sample.workloads=r;
   timing.observations[i].completedAtMs=clock;return r;
  }
  return cmd('sensorPods',o.sensorPods);
 };
 let oldDecision='PASS',reason=null;
 const context={fs:fakeFs,runtimeWindow,persistentRuntime,validatePriorExit,validateRuntimeContinuity,driverDiagnostics,crypto:{createHash:()=>({update:v=>({digest:()=>v.observedHash})})},spawnSync,requireLease:()=>{},process:{argv:['node','health',raw.mode],env:{BUILD_NUMBER:raw.build}},Date:ObservedDate,console:{warn:()=>{}},
  setTimeout:(fn,ms)=>{assert.equal(ms,16000);timing.wait={startedAtMs:clock,requestedMs:ms};clock+=ms+(spec.waitExtraMs??0)+(spec.clockAdjustmentMs??0);timing.wait.completedAtMs=clock;fn();},fetch:async()=>o.health,AbortSignal};
 try{await vm.runInNewContext('(async()=>{'+body+'})()',context);}catch(e){oldDecision='FAIL';reason=e.message;}
 timing.observations.forEach(x=>{x.ioDurationMs=x.completedAtMs-x.startedAtMs;});
 // All observations are now final. Policy receives this same untouched snapshot.
 raw.timing=timing;
 return {oldDecision,reason,report:writes['.devsecops/runtime-health.json'],trace};
}
fs.mkdirSync(new URL('fixtures/',out),{recursive:true});const records=[];
for(const mode of ['baseline','check'])for(const spec of specs){
 const raw=fixture(mode,spec),old=await original(raw,spec),bytes=JSON.stringify(raw),inputSha256=sha(bytes);
 if(spec.original){
  const prior=read('evidence/2026-11-02/real-v2-pipeline-integration/clock-'+mode+'-2000ms-input.json'),projected=structuredClone(raw);delete projected.timing;projected.observations.samples.forEach(x=>delete x.windowEndMs);
  assert.deepEqual(projected,prior,'original discovered finding/outcomes/timestamps changed');
 }
 const result=evaluate({component:mode==='baseline'?'falco-baseline':'falco-final',status:'success',raw},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(JSON.stringify(raw),bytes,'Policy mutated timing/event facts');
 const filename='fixtures/'+mode+'--'+spec.id+'.json',url=new URL(filename,out);
 if(fs.existsSync(url))assert.equal(sha(JSON.stringify(JSON.parse(fs.readFileSync(url)))),inputSha256,'before/after raw input drift');else fs.writeFileSync(url,JSON.stringify(raw,null,2)+'\n',{flag:'wx'});
 const assessmentEqual=JSON.stringify(result.runtimeAssessment??null)===JSON.stringify(old.report?.runtimeAssessment??null);
 const record={mode,name:spec.id,classification:raw.classification,oldDecision:old.oldDecision,standardDecision:result.decision,status:result.status,match:old.oldDecision===result.decision,
  assessmentEqual,rawPreserved:true,inputSha256,fixture:filename,oldReason:old.reason,policyReason:result.reason??null,timing:raw.timing,trace:old.trace,
  originalDiscoveryCase:!!spec.original,sourceSha256:sha(source),adapterSha256:sha(fs.readFileSync(new URL('infra/security/policy/falco-parent.mjs',root)))};
 if(phase==='after'){assert.ok(record.match,JSON.stringify(record));assert.ok(assessmentEqual,'window/assessment mismatch '+mode+' '+spec.id);}
 records.push(record);
}
if(phase==='before')assert.ok(records.some(r=>r.originalDiscoveryCase&&!r.match),'original drift not reproduced');
const result={phase,contract:'frozen-falco-observed-window-ms-v1',records,samples:records.length,match:records.filter(r=>r.match).length,drift:records.filter(r=>!r.match).length,
 rawFactsPreserved:records.every(r=>r.rawPreserved),classification:'CONTROLLED_COMPLETE_ORIGINAL_GATE_BODY_REPLAY',productionExecutionCount:0};
fs.writeFileSync(new URL('timing-'+phase+'.json',out),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({phase,cases:result.samples,match:result.match,drift:result.drift,originalDrifts:records.filter(r=>r.originalDiscoveryCase).map(({mode,oldDecision,standardDecision})=>({mode,oldDecision,standardDecision}))}));
