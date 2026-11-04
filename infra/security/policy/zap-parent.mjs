import fs from 'node:fs';import crypto from 'node:crypto';import {isDeepStrictEqual} from 'node:util';
import {classifyZap} from '../zap-policy.mjs';
// Consume complete original observations. No HTTP, scanning, proof generation or new classifier.
export function zapParent(raw){
 const lock=JSON.parse(fs.readFileSync(new URL('./versions/zap-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(lock.sourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen ZAP source changed');
 const absent=reason=>({status:'NOT_TESTED',decision:null,reason,rawEvidence:structuredClone(raw)});
 if(!raw||raw.schema!==1||raw.complete!==true||!Array.isArray(raw.observations))return absent('Complete original ZAP parent observations absent');
 if(raw.stage==='wrapper'){
  if(typeof raw.execution?.failed!=='boolean')return absent('Original selected Manager execution absent');
  const decision=raw.execution.failed||raw.module?.status==='failed'?'FAIL':raw.module?.status==='success'?'PASS':null;
  return decision?{status:decision,decision,rawEvidence:structuredClone(raw)}:absent('Selected ZAP result absent');
 }
 if(raw.stage!=='parent'||raw.command!==lock.command||!Number.isInteger(raw.execution?.exitStatus)||!raw.reports)return absent('Original parent command/process facts absent');
 let classification=null,classifierError=null;
 if(raw.classifierInput){try{classification=classifyZap(raw.classifierInput.report,raw.classifierInput.context,raw.classifierInput.approved);}catch(e){classifierError=e.message;}}
 let decision=raw.execution.exitStatus===0?'PASS':'FAIL';
 if(decision==='PASS'){
  const bytes=raw.reports['.devsecops/zap-gate.json'],native=raw.reports['.devsecops/zap-business-report.json'];
  if(typeof bytes!=='string'||typeof native!=='string'||!classification)return absent('Successful parent lacks complete original report/classifier facts');
  let report,data;try{report=JSON.parse(bytes);data=JSON.parse(native);}catch{return absent('Successful original report malformed');}
  if(report.status!=='success'||!isDeepStrictEqual(data,raw.classifierInput.report)||report.targetImage!==raw.classifierInput.context.targetImage||report.reportSha256!==raw.classifierInput.context.reportSha256)return absent('Classifier/report/target observations inconsistent');
  if(classification.blocking.length)decision='FAIL';
 }
 return {status:decision,decision,normalizedFacts:{classification,classifierError,execution:structuredClone(raw.execution),scope:'Existing whole passive-GET parent and cleanup acceptance; lower/unconfirmed alerts stay WARN facts, not a new parent WARN or PASS assertion about vulnerability absence'},rawEvidence:structuredClone(raw)};
}
