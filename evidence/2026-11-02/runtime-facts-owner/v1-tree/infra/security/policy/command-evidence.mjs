// Original command-audit.py and command-audit.mjs block parser errors and proven
// direct external flows. Unknown/review-only inventory does not fail the stage.
export function commandEvidence(raw){
 const r=raw?.report;
 if(!r||!Array.isArray(r.errors)||!Array.isArray(r.blockingFindings)||!Array.isArray(r.items)||!['success','failed'].includes(r.status))
  throw Error('POLICY_ERROR: complete command analysis evidence required');
 const decision=r.errors.length||r.blockingFindings.length?'FAIL':'PASS';
 if((r.status==='success')!==(decision==='PASS'))throw Error('POLICY_ERROR: command evidence internally inconsistent');
 return {decision,rawEvidence:structuredClone(raw),scope:'Combined static Python/script/SSH/interpreter findings; execution prerequisites are separate'};
}
// A parser crash can produce no JSON at all. The old wrapper then fails JSON.parse;
// preserve that operational FAIL instead of fabricating an empty successful report.
export function commandRunFacts(run){
 if(!run||!Number.isInteger(run.exitStatus)||typeof run.stdout!=='string'||typeof run.stderr!=='string')throw Error('POLICY_ERROR: command execution facts required');
 let report;try{report=JSON.parse(run.stdout);}catch{return {component:'semgrep-command-audit',status:'error',raw:structuredClone(run)};}
 return {component:'semgrep-command-audit',status:'success',raw:{report}};
}
