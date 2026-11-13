// Real local Node executions, not a Jenkins pipeline or migrated Regression guard.
import fs from 'node:fs';import assert from 'node:assert/strict';
import {createSourceOwner} from '../../../infra/security/summary-v2/owner.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url);
const lock=JSON.parse(fs.readFileSync(new URL('infra/security/policy/versions/regression-baseline-v1.json',root)));
const source=JSON.parse(fs.readFileSync(new URL('V1_IDENTITY.json',out))).gitHead,records=[];
for(const log of ['legacy-regression.log','rollback-regression.log']){
  const stdout=fs.readFileSync(new URL(log,out),'utf8');
  assert.match(stdout,/ℹ tests 147\b/);assert.match(stdout,/ℹ pass 147\b/);assert.match(stdout,/ℹ fail 0\b/);
  const raw={schema:1,stage:'command',complete:true,command:lock.command,execution:{status:0,signal:null,error:null},stdout,stderr:''},before=digest(raw);
  const binding={job:'controlled-local-regression-execution',build:1,project:'local-validation',source,candidate:'registry.invalid/local-regression@sha256:'+'0'.repeat(64),targetScope:'project',runId:log};
  const owner=createSourceOwner(binding),receipt=await owner.evaluateOnce('regression',{component:'regression',status:'success',raw});
  assert.equal(receipt.result.decision,'PASS');assert.equal(digest(raw),before);assert.equal(owner.counts().regression,1);
  records.push({classification:'REAL_CONTROLLED_LOCAL_NODE_EXECUTION_NOT_REAL_JENKINS_INTEGRATION',log,logSha256:sha(stdout),exitStatus:0,runnerTests:147,oldDecision:'PASS',standardDecision:receipt.result.decision,rawPreserved:true,receipt,localEvaluationCounts:owner.counts(),productionRegressionMigrated:false});
}
fs.writeFileSync(new URL('regression-execution-policy.json',out),JSON.stringify({samples:2,MATCH:2,DRIFT:0,records},null,2)+'\n');
console.log('LOCAL_REGRESSION_DIFFERENTIAL 2/2 MATCH; PRODUCTION_MIGRATION_NOT_TESTED');
