import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {GiB,validationHardFloor,productionRefreshRequirement,assessValidationBudget,
 loadValidationBudget,createLocalStorageSampler,scannerDatabaseIO,createValidationWorkspace,runOwnedValidationCommand,createValidationRefreshIO} from '../scanner-validation-guard.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
// Synthetic budgets only: no actual Trivy peak evidence is claimed.
const proof=()=>({status:'PROVEN_CONSERVATIVE_UPPER_BOUND',artifactDigests:{db:'sha256:'+'a'.repeat(64),'java-db':'sha256:'+'d'.repeat(64)},evidenceSha256:'b'.repeat(64),evidenceIdentity:'SYNTHETIC_UNIT_ONLY',domains:[{id:'guest-and-host',identity:'synthetic-device',capacityBytes:100*GiB,peakAdditionalBytes:4*GiB,instantaneousWriteBytes:GiB,cleanupBytes:GiB,otherWriterBytes:GiB,peakAdditionalInodes:100,instantaneousWindowMs:4000,boundIncludesDownloadExtractionOldNewTemp:true,boundIncludesScanAndReports:true,cleanupProven:true,backingAllocationProven:true}]});
const sample=()=>({at:Date.now(),diskPressure:false,unownedWriter:false,ownerValid:true,domains:[{id:'guest-and-host',identity:'synthetic-device',capacityBytes:100*GiB,availableBytes:64*GiB,inodesFree:100000}]});
const assess=(s=sample(),b=proof())=>assessValidationBudget(s,b);
function temp(){const root=fs.mkdtempSync(path.join(os.tmpdir(),'trivy-guard-test-'));fs.chmodSync(root,0o700);return fs.realpathSync(root);}
async function workspace(sampleFn=sample,budget=proof()) {const parent=temp();let w;try{w=await createValidationWorkspace({parent,runId:'trivy-validation-'+'a'.repeat(16),sample:sampleFn,budget});}catch(e){try{fs.rmdirSync(parent);}catch{}throw e;}return {parent,w,done(){if(fs.existsSync(w.directory))w.cleanup();fs.rmSync(parent,{recursive:true,force:true});}};}
test('production default delegates frozen IO and ignores ambient validation environment',()=>{
 const old=process.env.TRIVY_GUARD_MODE;process.env.TRIVY_GUARD_MODE='validation-only';
 try{const io=scannerDatabaseIO();assert.deepEqual(Object.keys(io),['assertOwner','upstream','download','read']);}
 finally{if(old===undefined)delete process.env.TRIVY_GUARD_MODE;else process.env.TRIVY_GUARD_MODE=old;}
 assert.equal(productionRefreshRequirement(100*GiB),27*GiB);assert.equal(validationHardFloor(100*GiB),23*GiB);
});
for(const mode of ['low','',null,'PRODUCTION'])test('invalid mode fails closed '+String(mode),()=>assert.throws(()=>scannerDatabaseIO({mode}),/EXPLICIT_VALIDATION/));
test('validation config cannot enter production',()=>assert.throws(()=>scannerDatabaseIO({validation:{floor:1}}),/VALIDATION_CONFIG_IN_PRODUCTION/));
test('validation mode has no production fallback',()=>{assert.throws(()=>scannerDatabaseIO({mode:'validation-only'}));assert.throws(()=>scannerDatabaseIO({mode:'validation-only',cacheDir:'/home/scanner/.cache/trivy',validation:{}}));});
test('exact boundary passes; one byte below fails',()=>{const b=proof(),s=sample();s.domains[0].availableBytes=30*GiB;assert.equal(assess(s,b).allowed,true);s.domains[0].availableBytes--;assert.equal(assess(s,b).allowed,false);});
test('monitor is not a substitute for peak budget',()=>{const b=proof();delete b.status;assert.equal(assessValidationBudget(sample(),b,Date.now(),true).allowed,false);});
for(const key of ['peakAdditionalBytes','instantaneousWriteBytes','cleanupBytes','otherWriterBytes','peakAdditionalInodes'])for(const v of [undefined,0,-1,NaN])test('invalid budget '+key+'/'+v,()=>{const b=proof();b.domains[0][key]=v;assert.equal(assess(sample(),b).allowed,false);});
for(const key of ['cleanupProven','backingAllocationProven','boundIncludesDownloadExtractionOldNewTemp','boundIncludesScanAndReports'])test('proof coverage required '+key,()=>{const b=proof();b.domains[0][key]=false;assert.equal(assess(sample(),b).allowed,false);});
for(const mutate of [s=>s.at-=1000,s=>s.at+=6000,s=>s.diskPressure=true,s=>s.ownerValid=false,s=>delete s.unownedWriter,s=>s.domains[0].identity='other',s=>s.domains[0].capacityBytes++,s=>s.domains[0].inodesFree=4000,s=>s.domains=[]])test('unsafe storage '+String(mutate),()=>{const s=sample();mutate(s);assert.equal(assess(s).allowed,false);});
test('backing domain cannot be omitted',()=>{const b=proof();b.domains.push({...b.domains[0],id:'physical-host',identity:'host'});assert.equal(assess(sample(),b).allowed,false);});
test('burst allowance covers full stop latency',()=>{const b=proof();b.domains[0].instantaneousWindowMs=3500;assert.equal(assess(sample(),b).allowed,false);});
test('numeric overflow cannot approve',()=>{const b=proof();b.domains[0].peakAdditionalBytes=Number.MAX_SAFE_INTEGER;assert.equal(assess(sample(),b).allowed,false);});
test('budget file hash, tamper and symlink checks',()=>{const d=temp();try{const f=d+'/proof.json',bytes=JSON.stringify(proof());fs.writeFileSync(f,bytes);assert.equal(loadValidationBudget(f,sha(bytes)).evidenceSha256,sha(bytes));fs.writeFileSync(f,bytes+' ');assert.throws(()=>loadValidationBudget(f,sha(bytes)),/HASH_MISMATCH/);fs.symlinkSync(f,d+'/link');assert.throws(()=>loadValidationBudget(d+'/link',sha(bytes)),/VALIDATION_PATH_REJECTED/);}finally{fs.rmSync(d,{recursive:true,force:true});}});
test('blocked preflight creates no run directory',async()=>{const parent=temp();try{await assert.rejects(createValidationWorkspace({parent,runId:'trivy-validation-'+'a'.repeat(16),sample,budget:{}}),/PREFLIGHT_BLOCKED/);assert.deepEqual(fs.readdirSync(parent),[]);}finally{fs.rmSync(parent,{recursive:true,force:true});}});
test('unsafe parent and run identity rejected',async()=>{const parent=temp();try{fs.chmodSync(parent,0o755);await assert.rejects(createValidationWorkspace({parent,runId:'trivy-validation-'+'a'.repeat(16),sample,budget:proof()}),/PRIVATE_TEMP_PARENT/);await assert.rejects(createValidationWorkspace({parent,runId:'../production',sample,budget:proof()}),/RUN_ID/);}finally{fs.rmSync(parent,{recursive:true,force:true});}});
test('running budget cannot be changed by caller',async()=>{const b=proof(),x=await workspace(sample,b);try{b.domains[0].cleanupBytes=1;assert.equal(x.w.budget.domains[0].cleanupBytes,GiB);assert.throws(()=>x.w.budget.domains[0].cleanupBytes=1);}finally{x.done();}});
