import test from 'node:test';import assert from 'node:assert/strict';import {observeExistingSonar} from './sonar-readonly-observation.mjs';
const origin={binding:{projectKey:'fixture',taskId:'task-fixture',requestedAnalysisId:'analysis-fixture'}};
test('Sonar missing credentials blocks without a request or invented skip',async()=>{const r=await observeExistingSonar({origin,request:()=>assert.fail('No request allowed')});assert.equal(r.status,'RUNTIME_OBSERVATION_BLOCKED');assert.equal(r.policyEvaluations,0);});
test('Sonar observations use two GETs, preserve facts and never rebind existing analysis',async()=>{
 const raw=[{task:{id:'task-fixture',analysisId:'analysis-fixture',componentKey:'fixture',status:'SUCCESS'}},{projectStatus:{status:'OK',conditions:[]}}],before=JSON.stringify(raw),requests=[];
 const r=await observeExistingSonar({origin,token:'SYNTHETIC_UNIT_TOKEN',request:async(url,options)=>{requests.push({url,options});return {status:200,json:async()=>raw[requests.length-1]};}});
 assert.equal(r.status,'OBSERVED_EXISTING_ANALYSIS_ONLY');assert.equal(requests.length,2);assert.ok(requests.every(x=>x.options.method==='GET'));assert.equal(JSON.stringify(raw),before);assert.equal(r.policyEvaluations,0);assert.equal(r.canonicalAdmission,'BLOCKED_PENDING_CURRENT_SOURCE_CANDIDATE_LINEAGE');assert.ok(!JSON.stringify(r).includes('SYNTHETIC_UNIT_TOKEN'));
});
test('Sonar API denial or analysis mismatch cannot become Policy PASS',async()=>{
 const denial=await observeExistingSonar({origin,token:'unit',request:async()=>({status:403})});assert.equal(denial.status,'RUNTIME_OBSERVATION_BLOCKED');
 const mismatch=await observeExistingSonar({origin,token:'unit',request:async()=>({status:200,json:async()=>({task:{id:'wrong'},projectStatus:{conditions:[]}})})});assert.equal(mismatch.status,'FACT_CONTRACT_INCOMPLETE');assert.equal(mismatch.policyEvaluations,0);
});
