import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import {isDeepStrictEqual} from 'node:util';import {evaluate} from './engine.mjs';
const out='evidence/2026-11-01/kyverno-parent/',read=p=>JSON.parse(fs.readFileSync(p));
const rbSource=fs.readFileSync('infra/security/rbac-contract.mjs','utf8').replace(/^import .*;\s*$/gm,'');
const adSource=fs.readFileSync('infra/security/admission-gate.mjs','utf8').replace(/^import .*;\s*$/gm,'');
const archived=read('evidence/2026-11-01/remaining-policy/archived-270.json').reports['admission-gate.json'];
const j=x=>({status:0,stdout:JSON.stringify(x),stderr:''}),plain=x=>({status:0,stdout:x,stderr:''});
function fixture(){
 const exceptions=read('infra/security/production-exceptions.json'),baseline=read('infra/security/production-baseline.json'),rb=read('evidence/2026-11-01/kyverno-policy/current-rbac-facts.json');
 const order=archived.cases.filter(c=>!exceptions.exceptions.some(e=>c.case.startsWith(e.id+'-')));
 for(const e of exceptions.exceptions){order.push(archived.exceptions.find(c=>c.id===e.id));order.push(...archived.cases.filter(c=>c.case.startsWith(e.id+'-')));}
 assert.equal(order.length,38);
 return {configuration:{baseline,exceptions,tools:read('infra/security/tools-lock.json'),scanner:read('infra/security/scanner-tools.json'),dependencies:read('infra/messaging/dependencies.json')},observations:{
 configurationReadSucceeded:true,sourceReadSucceeded:true,rbacReportWriteSucceeded:true,admissionReportWriteSucceeded:true,
 rbac:[j(rb.deployment),...rb.readChecks.map(c=>plain(c.value)),j(rb.role),j(rb.application)],policy:j({spec:baseline.spec}),
 owners:exceptions.exceptions.map(e=>j({items:[{metadata:{name:'fixture-'+e.id,ownerReferences:[e.owner]},spec:{serviceAccountName:e.serviceAccount,containers:[{name:e.container,image:e.image,env:e.environment,securityContext:{capabilities:{add:[]}}}],volumes:structuredClone(e.volumeSources)}}]})),
 probes:order.map(c=>({status:c.allowed?0:1,stdout:c.allowed?'{}':'',stderr:c.allowed?'':c.diagnostic})),
 workloads:j({items:[]})},classification:'SYNTHETIC_COMPLETE_PARENT_WITH_HISTORICAL_PROBE_RESULTS'};
}
function oldParent(raw){
 let stage='rbac',rbIndex=0,probeIndex=0,ownerIndex=0;const requests=[],writes=[];
 const files={
 'infra/security/tools-lock.json':raw.configuration.tools,'infra/security/production-baseline.json':raw.configuration.baseline,
 'infra/security/production-exceptions.json':raw.configuration.exceptions,'infra/security/scanner-tools.json':raw.configuration.scanner,'infra/messaging/dependencies.json':raw.configuration.dependencies};
 const getFile=path=>{
  if(path==='.git-sha'){if(!raw.observations.sourceReadSucceeded)throw Error('source read');return 'fixture-source';}
  if(!raw.observations.configurationReadSucceeded)throw Error('config read');
  if(!Object.hasOwn(files,path))throw Error('unknown fixture file');return JSON.stringify(files[path]);
 };
 const spawnSync=(_,args,options)=>{
  let r;
  if(stage==='rbac')r=raw.observations.rbac[rbIndex++];
  else if(args.includes('create')){requests.push(JSON.parse(options.input));r=raw.observations.probes[probeIndex++];}
  else if(args.includes('clusterpolicy'))r=raw.observations.policy;
  else if(args.includes('pods'))r=raw.observations.owners[ownerIndex++];
  else r=raw.observations.workloads;
  if(!r)throw Error('missing observed command');return {...r,error:r.error?new Error(r.error):undefined};
 };
 const context=()=>({JSON,structuredClone,isDeepStrictEqual,spawnSync,console:{log:()=>{}},fs:{readFileSync:getFile,mkdirSync:()=>{},writeFileSync:(p,value)=>{if(stage==='rbac'?!raw.observations.rbacReportWriteSucceeded:!raw.observations.admissionReportWriteSucceeded)throw Error('report write');writes.push({path:p,value:JSON.parse(value)});}}});
 try{vm.runInNewContext(rbSource,context());stage='admission';vm.runInNewContext(adSource,context());return {decision:'PASS',requests,writes};}
 catch(e){return {decision:'FAIL',reason:e.message,stage,requests,writes};}
}
const records=[];
function run(name,mutate,expected,branch){test('complete parent: '+name,()=>{
 const raw=fixture();mutate(raw);const before=JSON.stringify(raw),old=oldParent(raw),result=evaluate({component:'kyverno',status:'success',raw},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(old.decision,expected,'legacy fixture outcome: '+old.reason);assert.equal(result.decision,old.decision,result.reason);assert.equal(JSON.stringify(raw),before);assert.deepEqual(result.rawEvidence,raw);
 if(old.decision==='PASS')assert.deepEqual(result.workloadAudit,old.writes.find(w=>w.path.endsWith('admission-gate.json')).value.workloadAudit);
 assert.equal(result.securityLevel,'standard');
 // Preserve request and owner bindings from the unchanged original builders.
 records.push({name,branch,classification:raw.classification,oldDecision:old.decision,standardDecision:result.decision,rawPreserved:true,requests:old.requests,legacyReason:old.reason,policyReason:result.reason});
 });}
run('aligned-valid-exceptions',()=>{},'PASS','alignment/exception-valid');
for(const field of ['cel','preconditions','match'])run('policy-'+field+'-mismatch',r=>{const live=JSON.parse(r.observations.policy.stdout);if(field==='cel')live.spec.rules[0].validate.cel={expressions:[]};else live.spec.rules[0][field]={different:true};r.observations.policy=j(live);},'FAIL','alignment');
run('policy-rule-missing',r=>{const p=JSON.parse(r.observations.policy.stdout);p.spec.rules.shift();r.observations.policy=j(p);},'FAIL','alignment');
run('policy-not-enforce',r=>{const p=JSON.parse(r.observations.policy.stdout);p.spec.validationFailureAction='Audit';r.observations.policy=j(p);},'FAIL','alignment');
run('policy-unavailable',r=>r.observations.policy={status:1,stdout:'',stderr:'not found'},'FAIL','execution');
run('policy-malformed',r=>r.observations.policy=plain('{'),'FAIL','execution');
run('policy-metadata-missing',r=>r.observations.policy=j({}),'FAIL','alignment');
for(let i=0;i<3;i++)run('owner-absent-'+i,r=>r.observations.owners[i]=j({items:[]}),'FAIL','exception-owner');
run('owner-wrong',r=>{const p=JSON.parse(r.observations.owners[0].stdout);p.items[0].metadata.ownerReferences[0].uid='wrong';r.observations.owners[0]=j(p);},'FAIL','exception-owner');
run('exception-valid-request-denied',r=>r.observations.probes[25]={status:1,stdout:'',stderr:'devsecops-production-baseline denied'},'FAIL','exception-request');
run('exception-invalid-owner-allowed',r=>r.observations.probes[26]={status:0,stdout:'{}',stderr:''},'FAIL','exception-request');
run('exception-invalid-env-allowed',r=>r.observations.probes[27]={status:0,stdout:'{}',stderr:''},'FAIL','exception-request');
run('other-policy-denial-not-accepted',r=>r.observations.probes[26]={status:1,stdout:'',stderr:'unrelated-policy rule denied'},'FAIL','exception-policy');
run('same-policy-other-rule-frozen-coarse-check',r=>r.observations.probes[26]={status:1,stdout:'',stderr:'devsecops-production-baseline other-rule denied'},'PASS','exception-policy-existing-limitation');
const warned={metadata:{namespace:'fixture',name:'legacy'},kind:'Deployment',spec:{template:{spec:{hostPID:true,containers:[{name:'c',image:'image:latest'}]}}}};
run('PASS-plus-WARN',r=>r.observations.workloads=j({items:[warned]}),'PASS','aggregation');
run('WARN-plus-WARN',r=>r.observations.workloads=j({items:[warned,{...warned,metadata:{namespace:'fixture',name:'other'}}]}),'PASS','aggregation');
run('RBAC-FAIL-plus-WARN',r=>{r.observations.rbac[1]=plain('no');r.observations.workloads=j({items:[warned]});},'FAIL','aggregation');
run('exception-plus-WARN',r=>r.observations.workloads=j({items:[warned]}),'PASS','aggregation');
run('admission-FAIL-plus-WARN',r=>{r.observations.probes[1]={status:0,stdout:'{}',stderr:''};r.observations.workloads=j({items:[warned]});},'FAIL','aggregation');
for(const [name,change]of [
 ['controller-down',r=>r.observations.rbac[0]=j({status:{availableReplicas:0}})],
 ['RBAC-query-error',r=>r.observations.rbac[1]={status:1,stdout:'',stderr:'API down'}],
 ['CRD-get-denied',r=>r.observations.rbac[2]=plain('no')],
 ['role-rules-missing',r=>r.observations.rbac[3]=j({})],
 ['gitops-health-missing',r=>r.observations.rbac[4]=j({status:{}})],
 ['config-read-failure',r=>r.observations.configurationReadSucceeded=false],
 ['source-read-failure',r=>r.observations.sourceReadSucceeded=false],
 ['rbac-report-write-failure',r=>r.observations.rbacReportWriteSucceeded=false],
 ['admission-report-write-failure',r=>r.observations.admissionReportWriteSucceeded=false],
 ['admission-transport-error',r=>r.observations.probes[0]={status:null,error:'transport timeout',stdout:'',stderr:''}],
 ['owner-read-error',r=>r.observations.owners[0]={status:1,stdout:'',stderr:'unavailable'}],
 ['owner-metadata-malformed',r=>r.observations.owners[0]=j({items:[{}]})],
 ['workloads-unavailable',r=>r.observations.workloads={status:1,stdout:'',stderr:'unavailable'}],
 ['workloads-malformed',r=>r.observations.workloads=plain('{')],
 ['workload-template-missing',r=>r.observations.workloads=j({items:[{}]})],
 ['exception-container-missing',r=>{const p=JSON.parse(r.observations.owners[0].stdout);p.items[0].spec.containers=[];r.observations.owners[0]=j(p);}],
 ])run(name,change,'FAIL','execution');
for(const [name,change]of [
 ['extra-permission-incorrectly-allowed',r=>r.observations.probes[28]={status:0,stdout:'{}',stderr:''}],
 ['script-change-incorrectly-allowed',r=>r.observations.probes[36]={status:0,stdout:'{}',stderr:''}],
 ['exception-named-but-owner-not-bound',r=>{const p=JSON.parse(r.observations.owners[0].stdout);p.items[0].metadata.ownerReferences=[];r.observations.owners[0]=j(p);}],
 ['exception-script-metadata-missing',r=>{const p=JSON.parse(r.observations.owners[2].stdout);p.items[0].spec.volumes=[];r.observations.owners[2]=j(p);}],
 ['aggregate-rbac-role-lost',r=>r.observations.rbac[3]=j({rules:[]})],
 ['gitops-degraded',r=>r.observations.rbac[4]=j({status:{sync:{status:'Synced'},health:{status:'Degraded'}}})],
 ['gitops-out-of-sync',r=>r.observations.rbac[4]=j({status:{sync:{status:'OutOfSync'},health:{status:'Healthy'}}})],
 ['workload-malformed-volumes',r=>r.observations.workloads=j({items:[{...warned,spec:{template:{spec:{volumes:{bad:true},containers:[]}}}}]})],
 ['workload-read-error-with-zero-status',r=>r.observations.workloads={status:0,error:'transport error',stdout:'{}',stderr:''}],
 ['exception-read-malformed',r=>r.observations.owners[0]=plain('{')],
 ])run(name,change,'FAIL','remaining-error-or-exception');
test('missing parent evidence cannot PASS',()=>assert.equal(evaluate({component:'kyverno',status:'success',raw:{}}).decision,null));
test.after(()=>fs.writeFileSync(out+'parent-differential.json',JSON.stringify({scope:'Complete original rbac && admission script replay; no network or production mutation',records},null,2)));
