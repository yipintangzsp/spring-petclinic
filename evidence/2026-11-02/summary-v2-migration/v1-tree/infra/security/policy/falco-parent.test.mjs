import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';
import {runtimeWindow,persistentRuntime} from '../runtime/event-policy.mjs';import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from '../runtime/health-contract.mjs';import {evaluate} from './engine.mjs';
const out='evidence/2026-11-01/falco-parent/',read=p=>JSON.parse(fs.readFileSync(p)),archive=read('evidence/2026-11-01/remaining-policy/archived-270.json').reports,base=archive['runtime-baseline.json'],records=[];
const source=fs.readFileSync('infra/security/runtime/health.mjs','utf8').replace(/^import .*;\s*$/gm,'');
const response=x=>({status:0,stdout:typeof x==='string'?x:JSON.stringify(x),stderr:''}),file=value=>({value:typeof value==='string'?value:JSON.stringify(value)});
function fixture(mode){
 const lock=read('infra/security/runtime/lock.json'),now=Date.parse('2026-10-30T03:30:00Z');
 const pod={metadata:{uid:base.podUid,name:'sensor-fixture',labels:{'petclinic.devops.local/runtime-ruleset':lock.rulesetLabel}},spec:{nodeName:'devops',containers:[{name:'falco',image:base.image}]},status:{podIP:'127.0.0.1',containerStatuses:[{name:'falco',containerID:base.containerId,restartCount:base.restarts,ready:true,state:{running:{startedAt:base.runningSince}},lastState:{terminated:base.priorExit}}]}};
 const workloads={items:[{metadata:{name:'app',uid:'business-pod'},spec:{nodeName:'devops'},status:{containerStatuses:[{name:'main',containerID:'containerd://'+'a'.repeat(64),ready:true,state:{running:{startedAt:new Date(now-3600000).toISOString()}}}]}}]};
 return {classification:'CONTROLLED_COMPLETE_STAGE_WITH_HISTORICAL_SENSOR_IDENTITY',mode,now,build:'270',configuration:{},observations:{leaseOwned:true,files:{proof:file(read('infra/security/runtime/isolated-sensor-proof.json')),lock:file(lock),manifestHash:file(lock.manifestSha256),source:file(base.source),baseline:file(base)},baselineExists:true,ds:response({status:{desiredNumberScheduled:1,numberReady:1}}),sensorPods:response({items:[pod]}),node:response({status:{nodeInfo:{bootID:base.nodeBootId}}}),diagnosticLog:response(''),samples:[{log:response(''),workloads:response(workloads)},{log:response(''),workloads:response(workloads)}],health:{ok:true,status:200},mkdirSucceeded:true,baselineWriteSucceeded:true,reportWriteSucceeded:true}};
}
async function oracle(raw){
 const o=raw.observations,writes={},warnings=[];let time=raw.now,liveIndex=0,workloadIndex=0;
 class FrozenDate extends Date{constructor(...args){super(...(args.length?args:[time]));}static now(){return time;}}
 const fsFake={readFileSync:p=>{const key=p.endsWith('isolated-sensor-proof.json')?'proof':p.endsWith('lock.json')?'lock':p==='.git-sha'?'source':p.endsWith('runtime-baseline.json')?'baseline':p.endsWith('falco.json')?'manifestHash':null;const v=o.files[key];if(!v||v.error)throw Error('file read');return key==='manifestHash'?{observedHash:v.value}:v.value;},existsSync:()=>o.baselineExists,mkdirSync:()=>{if(!o.mkdirSucceeded)throw Error('mkdir');},writeFileSync:(p,v)=>{if(p.endsWith('runtime-baseline.json')?!o.baselineWriteSucceeded:!o.reportWriteSucceeded)throw Error('write');writes[p]=JSON.parse(v);}};
 const spawnSync=(_,a)=>{let r;if(a.includes('ds'))r=o.ds;else if(a.includes('node'))r=o.node;else if(a.includes('logs'))r=a.includes('--tail=500')?o.diagnosticLog:o.samples[liveIndex++].log;else if(a.includes('petclinic'))r=o.samples[workloadIndex++].workloads;else r=o.sensorPods;if(!r)throw Error('observation missing');return r;};
 const context={fs:fsFake,runtimeWindow,persistentRuntime,validatePriorExit,validateRuntimeContinuity,driverDiagnostics,crypto:{createHash:()=>({update:v=>({digest:()=>v.observedHash})})},spawnSync,requireLease:()=>{if(!o.leaseOwned)throw Error('lease');},process:{argv:['node','health',raw.mode],env:{BUILD_NUMBER:raw.build}},Date:FrozenDate,console:{warn:v=>warnings.push(v)},setTimeout:fn=>{time+=16000;fn();},fetch:async()=>{if(o.health.error)throw Error('health query');return o.health;},AbortSignal};
 try{await vm.runInNewContext('(async()=>{'+source+'})()',context);return {decision:'PASS',report:writes['.devsecops/runtime-health.json'],warnings};}catch(error){return {decision:'FAIL',reason:error.message,warnings};}
}
function event(raw,index,patch={},rule='Platform Runtime Sensitive Write'){
 return {time:new Date(raw.now+index*16000-10000).toISOString(),rule,priority:'Warning',output_fields:{'k8s.ns.name':'petclinic','k8s.pod.name':'app','container.name':'main','container.id':'a'.repeat(12),'evt.res':'SUCCESS','evt.type':'openat','evt.arg.name':'/etc/ld.so.preload','proc.name':'cp',...patch}};
}
function events(raw,index,items){raw.observations.samples[index].log=response(items.map(e=>JSON.stringify(e)).join('\n'));}
function repeat(raw,index,patch={},rule){const a=event(raw,index,patch,rule),b={...a,time:new Date(Date.parse(a.time)+1000).toISOString()};events(raw,index,[a,b]);}
function alterPod(raw,change){const p=JSON.parse(raw.observations.sensorPods.stdout);change(p.items[0]);raw.observations.sensorPods=response(p);}
function run(mode,name,change,expected,branch){test(mode+' full Falco '+name,async()=>{
 const raw=fixture(mode);change(raw);const before=JSON.stringify(raw),old=await oracle(raw),p=evaluate({component:mode==='baseline'?'falco-baseline':'falco-final',status:'success',raw});
 assert.equal(old.decision,expected,old.reason);assert.equal(p.decision,old.decision,p.reason);assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);
 if(p.decision==='PASS'){assert.deepEqual(JSON.parse(JSON.stringify(p.runtimeAssessment)),old.report.runtimeAssessment);assert.deepEqual(JSON.parse(JSON.stringify(p.liveChecks)),old.report.liveChecks);assert.deepEqual(JSON.parse(JSON.stringify(p.diagnostics)),old.report.diagnostics);assert.deepEqual(JSON.parse(JSON.stringify(p.historicalWarning)),old.report.historicalWarning);}
 records.push({mode,name,branch,classification:raw.classification,oldDecision:old.decision,standardDecision:p.decision,rawPreserved:true,legacyReason:old.reason,policyReason:p.reason,warningKinds:p.liveChecks?.[0].window.warnings});
});}
for(const mode of ['baseline','check']){
 run(mode,'healthy-empty',()=>{},'PASS','healthy');
 run(mode,'historical-driver-error',r=>r.observations.diagnosticLog=response('FATAL historical startup'),'PASS','historical');
 run(mode,'current-fatal',r=>r.observations.samples[0].log=response('FATAL current driver'),'FAIL','health');
 run(mode,'persistent-sensitive-write',r=>{repeat(r,0);repeat(r,1);},'FAIL','persistent-events');
 run(mode,'persistent-shadow-read',r=>{for(const i of [0,1])repeat(r,i,{'evt.arg.name':'/etc/shadow','proc.name':'cat'},'Platform Runtime Sensitive Read');},'FAIL','persistent-events');
 run(mode,'transient-repeated',r=>repeat(r,0),'PASS','transient');
 run(mode,'single-current-candidate',r=>events(r,0,[event(r,0)]),'PASS','transient');
 run(mode,'denied-write',r=>repeat(r,0,{'evt.res':'EROFS'}),'PASS','prevented-events');
 run(mode,'isolated-test',r=>repeat(r,0,{'k8s.ns.name':'devsecops-test'}),'PASS','isolated-events');
 run(mode,'stale-events',r=>{const e=event(r,0);e.time=new Date(r.now-60000).toISOString();events(r,0,[e]);},'PASS','historical');
 run(mode,'priority-alone-not-blocking',r=>{const e=event(r,0,{},'Platform Runtime Shell');e.priority='Critical';events(r,0,[e]);},'PASS','event-evidence');
 run(mode,'different-process-not-persistent',r=>{repeat(r,0);repeat(r,1,{'proc.name':'cat'});},'PASS','event-evidence');
 run(mode,'duplicate-not-two-events',r=>{const e=event(r,0);events(r,0,[e,e]);},'PASS','event-evidence');
 run(mode,'malformed-json-counted-not-fatal',r=>r.observations.samples[0].log=response('{invalid'),'PASS','existing-parser-semantics');
 run(mode,'second-window-fatal',r=>{repeat(r,0);r.observations.samples[1].log=response('Error attaching BPF probe');},'FAIL','health');
 for(const [name,change]of [
 ['lease-unowned',r=>r.observations.leaseOwned=false],['proof-missing',r=>delete r.observations.files.proof],['proof-cleanup-failed',r=>{const p=JSON.parse(r.observations.files.proof.value);p.cleanup.removed=false;r.observations.files.proof=file(p);}],
 ['manifest-mismatch',r=>r.observations.files.manifestHash=file('changed')],['DS-down',r=>r.observations.ds=response({status:{desiredNumberScheduled:1,numberReady:0}})],
 ['sensor-missing',r=>r.observations.sensorPods=response({items:[]})],['sensor-wrong-node',r=>alterPod(r,p=>p.spec.nodeName='other')],['sensor-wrong-image',r=>alterPod(r,p=>p.spec.containers[0].image='wrong')],
 ['sensor-wrong-rules',r=>alterPod(r,p=>p.metadata.labels['petclinic.devops.local/runtime-ruleset']='wrong')],['sensor-not-ready',r=>alterPod(r,p=>p.status.containerStatuses[0].ready=false)],
 ['log-query-failed',r=>r.observations.samples[0].log={status:1,stdout:'',stderr:'unavailable'}],['historical-query-failed',r=>r.observations.diagnosticLog={status:1,stdout:'',stderr:'unavailable'}],
 ['workload-query-failed',r=>r.observations.samples[0].workloads={status:1,stdout:'',stderr:'unavailable'}],['health-down',r=>r.observations.health={ok:false,status:500}],['health-query-error',r=>r.observations.health={error:true}],
 ['report-write-failed',r=>r.observations.reportWriteSucceeded=false],['output-dir-failed',r=>r.observations.mkdirSucceeded=false],['sensor-response-malformed',r=>r.observations.sensorPods=response('{')],['source-read-failed',r=>r.observations.files.source={error:true}],
 ])run(mode,name,change,'FAIL','execution-health');
}
run('baseline','recent-start',r=>alterPod(r,p=>p.status.containerStatuses[0].state.running.startedAt=new Date(r.now-1000).toISOString()),'FAIL','baseline-identity');
run('baseline','invalid-restart-count',r=>alterPod(r,p=>p.status.containerStatuses[0].restartCount=-1),'FAIL','baseline-identity');
run('baseline','baseline-write-failed',r=>r.observations.baselineWriteSucceeded=false,'FAIL','baseline-write');
run('baseline','clean-prior-exit',r=>alterPod(r,p=>p.status.containerStatuses[0].lastState.terminated={reason:'Completed',exitCode:0}),'PASS','baseline-history');
for(const [name,change]of [['missing-baseline',r=>r.observations.baselineExists=false],['foreign-build',r=>{const b=JSON.parse(r.observations.files.baseline.value);b.build='wrong';r.observations.files.baseline=file(b);}],['new-restart',r=>alterPod(r,p=>p.status.containerStatuses[0].restartCount++)],['new-container',r=>alterPod(r,p=>p.status.containerStatuses[0].containerID='new')],['new-node-boot',r=>r.observations.node=response({status:{nodeInfo:{bootID:'new'}}})]])run('check',name,change,'FAIL','final-continuity');
for(const mode of ['baseline','check']){
 run(mode,'outside-business-scope',r=>repeat(r,0,{'k8s.ns.name':'unrelated'}),'PASS','event-scope');
 run(mode,'unconfirmed-container-identity',r=>repeat(r,0,{'container.id':'b'.repeat(12)}),'PASS','event-scope');
 run(mode,'ordinary-file-read',r=>repeat(r,0,{'evt.arg.name':'/etc/passwd','proc.name':'cat'},'Platform Runtime Sensitive Read'),'PASS','event-scope');
 run(mode,'normalized-path-not-critical',r=>repeat(r,0,{'evt.arg.name':'/etc/cron.d/../resolv.conf'}),'PASS','event-scope');
 run(mode,'missing-event-timestamp',r=>{const e=event(r,0);delete e.time;events(r,0,[e]);},'PASS','event-scope');
 run(mode,'missing-rule',r=>{const e=event(r,0);delete e.rule;events(r,0,[e]);},'PASS','existing-parser-semantics');
 run(mode,'second-window-query-fails',r=>{repeat(r,0);r.observations.samples[1].log={status:1,stdout:'',stderr:'failed'};},'FAIL','execution-health');
 run(mode,'workload-response-malformed',r=>r.observations.samples[0].workloads=response('{'),'FAIL','execution-health');
 run(mode,'lock-response-malformed',r=>r.observations.files.lock=file('{'),'FAIL','execution-health');
 run(mode,'node-response-malformed',r=>r.observations.node=response('{'),'FAIL','execution-health');
 run(mode,'live-rule-output-text-is-not-driver-fatal',r=>{const e=event(r,0,{},'Platform Runtime Shell');e.output='fatal error loading BPF';events(r,0,[e]);},'PASS','event-evidence');
}
run('check','foreign-baseline-source',r=>{const b=JSON.parse(r.observations.files.baseline.value);b.source='other';r.observations.files.baseline=file(b);},'FAIL','final-continuity');
run('check','baseline-JSON-malformed',r=>r.observations.files.baseline=file('{'),'FAIL','final-continuity');
run('check','running-start-changed',r=>alterPod(r,p=>p.status.containerStatuses[0].state.running.startedAt=new Date(r.now-600000).toISOString()),'FAIL','final-continuity');
run('baseline','boot-identity-missing',r=>r.observations.node=response({status:{nodeInfo:{bootID:''}}}),'FAIL','baseline-identity');
run('baseline','current-start-unknown',r=>alterPod(r,p=>p.status.containerStatuses[0].state={running:{}}),'FAIL','baseline-identity');
for(const mode of ['baseline','check'])run(mode,'proof-cases-unavailable-at-report',r=>{const p=JSON.parse(r.observations.files.proof.value);delete p.cases;r.observations.files.proof=file(p);},'FAIL','report-serialization');
test('uncaptured Falco facts are not PASS',()=>assert.equal(evaluate({component:'falco-baseline',status:'success',raw:{}}).decision,null));
test.after(()=>fs.writeFileSync(out+'differential.json',JSON.stringify({records},null,2)));
