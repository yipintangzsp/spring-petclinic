import fs from 'node:fs';import crypto from 'node:crypto';
// Consume complete observations from the unchanged command-audit + Semgrep parent.
// No AST, taint inference, pattern matching, scanner subprocess or severity remapping here.
export function commandParent(raw){
 const baseline=JSON.parse(fs.readFileSync(new URL('./versions/command-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(baseline.sourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen command-analysis source changed');
 const absent=reason=>({decision:null,status:'NOT_TESTED',reason,rawEvidence:structuredClone(raw)});
 if(!raw||raw.schema!==1||raw.complete!==true)return absent('Complete original command-analysis execution facts absent');
 if(raw.stage==='wrapper'){
  if(!raw.execution||typeof raw.execution.failed!=='boolean'||!Array.isArray(raw.observations))return absent('Original wrapper observations absent');
  const decision=raw.execution.failed||raw.module?.status==='failed'?'FAIL':raw.module?.status==='success'?'PASS':null;
  return decision?{decision,status:decision,normalizedFacts:{execution:structuredClone(raw.execution),module:structuredClone(raw.module),observations:structuredClone(raw.observations)},rawEvidence:structuredClone(raw)}:absent('Selected module result absent');
 }
 if(raw.stage!=='parent'||raw.command!==baseline.command||!Array.isArray(raw.operations)||!raw.operations.length)return absent('Frozen combined parent facts absent');
 const first=raw.operations[0];if(first.stage!=='command-audit'||!first.execution||!Number.isInteger(first.execution.exitStatus))return absent('Command-audit execution incomplete');
 if(first.execution.exitStatus===0){const second=raw.operations[1];if(raw.operations.length!==2||second?.stage!=='semgrep'||!Number.isInteger(second.execution?.exitStatus))return absent('Successful audit lacks complete following Semgrep execution');}
 else if(raw.operations.length!==1)return absent('Original && short-circuit facts inconsistent');
 for(const op of raw.operations){
  if(!Array.isArray(op.observations)||!op.reports)return absent('Original report/lifecycle observations uncaptured');
  if(op.execution.exitStatus===0){const paths=op.stage==='command-audit'?['.devsecops/command-audit.json']:['.devsecops/semgrep-gate.json','.devsecops/semgrep-native.json'];if(paths.some(p=>typeof op.reports[p]!=='string'))return absent('Successful operation lacks captured native report');}
 }
 const decision=raw.operations.some(x=>x.execution.exitStatus!==0)?'FAIL':'PASS';
 return {decision,status:decision,normalizedFacts:{operations:structuredClone(raw.operations),scope:'Existing combined stage acceptance; unconfirmed findings retained without a new stage WARN',aggregation:'Original short-circuit &&, not a second finding classifier'},rawEvidence:structuredClone(raw)};
}
