import fs from 'node:fs';import crypto from 'node:crypto';
// Read only frozen original validation outcomes. Never issue approval, sign, write Git, or self-approve.
export function promotionEvidence(raw){
 const b=JSON.parse(fs.readFileSync(new URL('./versions/promotion-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(b.sourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen Promotion source changed');
 const absent=reason=>({status:'NOT_TESTED',decision:null,reason,rawEvidence:structuredClone(raw)});
 if(!raw||raw.schema!==1||!raw.complete)return absent('Complete original promotion observations absent');
 if(raw.stage==='eligibility'){
  if(!raw.conditions||typeof raw.conditions.selected!=='boolean')return absent('Original stage selection not observed');
  if(!raw.conditions.selected)return {status:'SKIPPED',decision:null,normalizedFacts:structuredClone(raw.conditions),rawEvidence:structuredClone(raw)};
  if(!raw.execution||typeof raw.execution.failed!=='boolean')return absent('Selected parent completion unknown');
  const decision=raw.execution.failed?'FAIL':'PASS';return {status:decision,decision,normalizedFacts:structuredClone(raw),rawEvidence:structuredClone(raw)};
 }
 if(!['candidate-sbom','sign-approve','dry-run','deploy','private-main'].includes(raw.stage)||!Number.isInteger(raw.execution?.exitStatus)||!Array.isArray(raw.observations)||!raw.reports)return absent('Original operation completion/report observations missing');
 const successReports={'candidate-sbom':'.devsecops/candidate-sbom.json','sign-approve':'.devsecops/approval-signing.json','dry-run':'.devsecops/promotion-result.json',deploy:'.devsecops/promotion-result.json','private-main':'target/platform/promotion.json'};
 if(raw.execution.exitStatus===0&&typeof raw.reports[successReports[raw.stage]]!=='string')return absent('Successful operation report uncaptured');
 const decision=raw.execution.exitStatus===0?'PASS':'FAIL';return {status:decision,decision,normalizedFacts:{stage:raw.stage,execution:structuredClone(raw.execution),inputIdentity:structuredClone(raw.inputIdentity),observations:structuredClone(raw.observations),reports:structuredClone(raw.reports)},rawEvidence:structuredClone(raw)};
}
