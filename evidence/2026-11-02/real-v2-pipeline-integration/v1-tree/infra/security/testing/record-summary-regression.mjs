import fs from 'node:fs';
import {createSourceOwner} from '../summary-v2/owner.mjs';
import {digest} from '../summary-v2/codec.mjs';
const base='evidence/2026-11-02/summary-v2-migration/';
const command=JSON.parse(fs.readFileSync('infra/security/policy/versions/regression-baseline-v1.json')).command;
const rows=[];
for(const [log,exitCode,environment]of [['legacy-regression.log',1,'sandbox localhost listen EPERM'],['legacy-regression-loopback.log',0,'authorized localhost loopback test execution']]){
 const stdout=fs.readFileSync(base+log,'utf8'),raw={schema:1,stage:'command',complete:true,command,execution:{status:exitCode,signal:null,error:null},stdout,stderr:''},before=digest(raw);
 const binding={job:'local-regression-observation',build:1,project:'fixture',source:'c'.repeat(40),candidate:'registry.invalid/fixture@sha256:'+'a'.repeat(64),targetScope:'project',runId:log};
 const owner=createSourceOwner(binding),receipt=await owner.evaluateOnce('regression',{component:'regression',status:'success',raw});
 const oldDecision=exitCode===0?'PASS':'FAIL';
 rows.push({classification:'REAL_CONTROLLED_LOCAL_NODE_TEST_EXECUTION',command,log,environment,exitCode,oldDecision,standardDecision:receipt.result?.decision,error:receipt.error,
  match:oldDecision===receipt.result?.decision,rawUnchanged:before===digest(raw),evaluationCounts:owner.counts(),productionConsumerMigrated:false});
}
fs.writeFileSync(base+'actual-regression-differential.json',JSON.stringify({rows,allMatch:rows.every(x=>x.match&&x.rawUnchanged)},null,2)+'\n');
if(!rows.every(x=>x.match&&x.rawUnchanged))process.exitCode=1;
console.log(JSON.stringify(rows.map(({exitCode,oldDecision,standardDecision,match})=>({exitCode,oldDecision,standardDecision,match}))));
