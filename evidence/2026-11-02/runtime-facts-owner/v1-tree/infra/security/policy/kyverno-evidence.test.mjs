import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import {evaluate} from './engine.mjs';
const dir='evidence/2026-11-01/kyverno-policy/',r=JSON.parse(fs.readFileSync('evidence/2026-11-01/remaining-policy/archived-270.json')).reports['admission-gate.json'],records=[];
const src=fs.readFileSync('infra/security/admission-gate.mjs','utf8');const probe=src.slice(src.indexOf('function probe('),src.indexOf('\ntry{'));
async function diff(name,raw,kind,expected){
 const before=JSON.stringify(raw);let old;
 try{const context={spawnSync:()=>({status:raw.result.allowed?0:1,stderr:raw.result.diagnostic,error:raw.executionError?new Error('fixture transport error'):null}),JSON};vm.runInNewContext(probe+'\nprobe({},'+raw.expectedDenial+')',context);old='PASS';}catch{old='FAIL';}
 const actual=evaluate({component:'kyverno-admission',status:'success',raw});assert.equal(old,expected);assert.equal(actual.decision,old);assert.equal(JSON.stringify(raw),before);assert.deepEqual(actual.rawEvidence,raw);records.push({name,kind,oldDecision:old,standardDecision:actual.decision,rawPreserved:true});
}
for(const c of r.cases)test('archived admission '+c.case,()=>diff(c.case,{expectedDenial:c.mode==='FAIL',result:c,source:r.source},'HISTORICAL_ARCHIVE', 'PASS'));
for(const e of r.exceptions)test('archived exception '+e.id,()=>diff(e.id,{expectedDenial:false,result:e,exceptionIdentity:r.scope.exceptions.find(x=>x.id===e.id),source:r.source},'HISTORICAL_ARCHIVE','PASS'));
for(const [name,raw]of [['violation-incorrectly-allowed',{expectedDenial:true,result:{allowed:true,diagnostic:''}}],['valid-incorrectly-denied',{expectedDenial:false,result:{allowed:false,diagnostic:'devsecops-production-baseline'}}],['unrelated-error-not-policy-denial',{expectedDenial:true,result:{allowed:false,diagnostic:'connection refused'}}],['transport-error',{expectedDenial:false,result:{allowed:true,diagnostic:''},executionError:true}]])test(name,()=>diff(name,raw,'SYNTHETIC_UNIT_ONLY','FAIL'));
const good={deployment:{status:{availableReplicas:1}},readChecks:[{value:'yes'},{value:'yes'}],role:{rules:[{apiGroups:['apiextensions.k8s.io'],resources:['customresourcedefinitions'],verbs:['get']}]},application:{status:{sync:{status:'Synced'},health:{status:'Healthy'}}}};
const rbSrc=fs.readFileSync('infra/security/rbac-contract.mjs','utf8').replace(/^import .*;\s*$/gm,'');
for(const [name,change,expected]of [['valid',()=>{},'PASS'],['unavailable',x=>x.deployment.status.availableReplicas=0,'FAIL'],['read-denied',x=>x.readChecks[0].value='no','FAIL'],['aggregate-missing',x=>x.role.rules=[],'FAIL'],['out-of-sync',x=>x.application.status.sync.status='OutOfSync','FAIL'],['unhealthy',x=>x.application.status.health.status='Degraded','FAIL']])test('RBAC original Gate '+name,()=>{
 const raw=structuredClone(good);change(raw);const before=JSON.stringify(raw);let index=0;const spawnSync=(_,a)=>({status:0,stdout:a.includes('auth')?raw.readChecks[index++].value:JSON.stringify(a.includes('clusterrole')?raw.role:a.includes('application')?raw.application:raw.deployment)});
 let old;try{vm.runInNewContext(rbSrc,{spawnSync,JSON,fs:{mkdirSync:()=>{},readFileSync:()=> 'fixture',writeFileSync:()=>{}}});old='PASS';}catch{old='FAIL';}
 const actual=evaluate({component:'kyverno-rbac',status:'success',raw});assert.equal(old,expected);assert.equal(actual.decision,old);assert.equal(JSON.stringify(raw),before);records.push({name:'rbac-'+name,kind:'SYNTHETIC_UNIT_ONLY',oldDecision:old,standardDecision:actual.decision,rawPreserved:true});
});
test('current read-only RBAC observations match unchanged original Gate',()=>{
 const raw=JSON.parse(fs.readFileSync(dir+'current-rbac-facts.json')),before=JSON.stringify(raw);let index=0;
 const spawnSync=(_,a)=>({status:0,stdout:a.includes('auth')?raw.readChecks[index++].value:JSON.stringify(a.includes('clusterrole')?raw.role:a.includes('application')?raw.application:raw.deployment)});
 let old;try{vm.runInNewContext(rbSrc,{spawnSync,JSON,fs:{mkdirSync:()=>{},readFileSync:()=> 'observed-source',writeFileSync:()=>{}}});old='PASS';}catch{old='FAIL';}
 const actual=evaluate({component:'kyverno-rbac',status:'success',raw});assert.equal(actual.decision,old);assert.equal(JSON.stringify(raw),before);
 records.push({name:'current-rbac-observations',kind:'REAL_READ_ONLY_OBSERVATIONS',oldDecision:old,standardDecision:actual.decision,rawPreserved:true});
});
test('missing evidence is not PASS',()=>{for(const component of ['kyverno-rbac','kyverno-admission'])assert.equal(evaluate({component,status:'success',raw:{}}).decision,null);});
test.after(()=>fs.writeFileSync(dir+'differential.json',JSON.stringify({records},null,2)));
