import fs from 'node:fs';import crypto from 'node:crypto';
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
// The original node:test / Jenkins wrapper produces facts. Policy never runs/imports that runner.
export function regressionEvidence(raw){
 const baseline=JSON.parse(fs.readFileSync(new URL('./versions/regression-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(baseline.sourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen Regression source changed');
 const absent=reason=>({status:'NOT_TESTED',decision:null,reason,rawEvidence:structuredClone(raw)});
 if(!object(raw)||raw.schema!==1||raw.complete!==true)return absent('Complete original Regression execution evidence absent');
 if(raw.stage==='command'){
  if(raw.command!==baseline.command)return absent('Execution not bound to frozen Regression command');
  const r=raw.execution;if(!object(r)||!Object.hasOwn(r,'status')||!Object.hasOwn(r,'signal')||!Object.hasOwn(r,'error')||typeof raw.stdout!=='string'||typeof raw.stderr!=='string')return absent('Original execution status/output observations missing');
  if(r.status!==null&&(!Number.isInteger(r.status)||r.status<0))return absent('Invalid observed process exit status');
  if(r.status===null&&!r.signal&&!r.error)return absent('Process completion unknown');
  // Production does not parse TAP or enforce a hardcoded count, baseline revision or scan digest.
  const decision=r.error||r.signal||r.status!==0?'FAIL':'PASS';
  return {status:decision,decision,normalizedFacts:{command:raw.command,execution:structuredClone(r),stdout:raw.stdout,stderr:raw.stderr,testFiles:structuredClone(raw.testFiles),observedInputs:structuredClone(raw.observedInputs),runnerCounts:structuredClone(raw.runnerCounts)},rawEvidence:structuredClone(raw)};
 }
 if(raw.stage==='wrapper'){
  if(!object(raw.execution)||typeof raw.execution.failed!=='boolean'||!Array.isArray(raw.observations))return absent('Complete original wrapper evidence absent');
  // The production adapter is enforce-only. Missing reports are not reinterpreted as successful scans.
  const decision=raw.execution.failed||raw.module?.status==='failed'?'FAIL':raw.module?.status==='success'?'PASS':null;
  if(decision===null)return absent('Selected Regression module result unavailable');
  return {status:decision,decision,normalizedFacts:{module:structuredClone(raw.module),execution:structuredClone(raw.execution),observations:structuredClone(raw.observations)},rawEvidence:structuredClone(raw)};
 }
 return absent('Unsupported Regression evidence stage');
}
