// Read-only blocker reproduction. No Summary/Policy/Gate source bytes are written.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import test from 'node:test';
import {evaluate} from '../../../infra/security/policy/engine.mjs';
import {validateGate} from '../../../infra/security/promotion/contract.mjs';
import {fixture} from '../../../infra/security/policy/promotion-fixtures.mjs';
const out='evidence/2026-11-02/policy-metadata-summary-integration/';
const target=path.resolve('infra/security/security-summary.mjs');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const results=[];
for(const [component,file] of [
 ['security-approval-promotion','evidence/2026-11-01/promotion-parent/fixtures/candidate-sbom--valid.json'],
 ['regression','evidence/2026-11-01/regression-parent/fixtures/command--unchanged-current-suite.json']
])test(component+': exact source constraint blocks even a semantic no-op change',()=>{
 const document=JSON.parse(fs.readFileSync(file,'utf8')),raw=document.raw??document,before=JSON.stringify(raw);
 const baseline=evaluate({component,status:'success',raw});assert.equal(baseline.decision,'PASS');
 const original=fs.readFileSync,bytes=original(target),proposed=Buffer.concat([bytes,Buffer.from('\n// CONTROLLED PREFLIGHT: additive metadata proposal; no on-disk change.\n')]);
 let caught=null;
 try{
  fs.readFileSync=function(file,...args){
   const p=file instanceof URL?fileURLToPath(file):typeof file==='string'?path.resolve(file):null;
   if(p===target){const encoding=typeof args[0]==='string'?args[0]:args[0]?.encoding;return encoding?proposed.toString(encoding):Buffer.from(proposed);}
   return original.call(this,file,...args);
  };
  try{evaluate({component,status:'success',raw});}catch(error){caught=error.message;}
 }finally{fs.readFileSync=original;}
 assert.match(caught,/^POLICY_ERROR: frozen (Promotion|Regression) source changed$/);
 assert.equal(hash(fs.readFileSync(target)),hash(bytes));
 assert.equal(evaluate({component,status:'success',raw}).decision,'PASS');
 assert.equal(JSON.stringify(raw),before);
 results.push({component,classification:'CONTROLLED_IN_MEMORY_SOURCE_INTEGRITY_PROBE',baselinePolicyDecision:'PASS',proposedSourceChange:'append comment only; no rule or output changes',proposedSourceSha256:hash(proposed),baselineSourceSha256:hash(bytes),observedError:caught,rawFactsPreserved:true,onDiskSourceUnchanged:true,restoredPolicyDecision:'PASS',notARealScannerOrReleaseExecution:true});
 fs.writeFileSync(out+'source-lock-blocker-proof.json',JSON.stringify({blockerConfirmed:true,probes:results},null,2));
});
test('Promotion JSON contract accepts unknown policy fields; source-lock constraint is distinct',()=>{
 const data=fixture('candidate-sbom').gate,before=structuredClone(data),old=validateGate(data);
 const result=evaluate({component:'semgrep',status:'success',raw:{findings:[]}});
 data.summary.policy={policyVersion:result.policyVersion,securityLevel:result.securityLevel,effectivePolicy:result.effectivePolicy,appliedOverrides:result.appliedOverrides,status:result.status};
 assert.equal(validateGate(data),old);
 const clone=structuredClone(data);delete clone.summary.policy;assert.deepEqual(clone,before);
 fs.writeFileSync(out+'promotion-json-additive-precheck.json',JSON.stringify({classification:'CONTROLLED_CONTRACT_ONLY_NOT_SUMMARY_INTEGRATION',knownFieldsUnchanged:true,unknownPolicyObjectAccepted:true,metadataFromExistingEngine:true,approvalOrSigningExecuted:false,releaseOrPromotionExecuted:false},null,2));
});
