import fs from 'node:fs';
import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {gitleaksEvidence} from './gitleaks-evidence.mjs';
import {verifyGitleaksSourceLock} from './gitleaks-source-lock.mjs';

// Existing execution receipts only. No scanner, source read, network or new classifier.
export function gitleaksParent(raw){
 const {lock}=verifyGitleaksSourceLock();
 const absent=reason=>({status:'NOT_TESTED',decision:null,reason,rawEvidence:structuredClone(raw)});
 if(!raw||raw.schema!==1||raw.complete!==true||!Array.isArray(raw.observations))return absent('Complete original Gitleaks execution observations absent');
 if(raw.stage==='wrapper'){
  if(typeof raw.execution?.failed!=='boolean')return absent('Original selected parent wrapper execution absent');
  const decision=raw.execution.failed||raw.module?.status==='failed'?'FAIL':raw.module?.status==='success'?'PASS':null;
  return decision?{status:decision,decision,normalizedFacts:{execution:structuredClone(raw.execution),module:structuredClone(raw.module),scope:'Frozen production enforce-only selected Gitleaks wrapper'},rawEvidence:structuredClone(raw)}:absent('Selected original Gitleaks result absent');
 }
 if(raw.stage!=='parent'||raw.command!==lock.command||!Number.isInteger(raw.execution?.exitStatus)||!raw.reports)return absent('Original parent command/process observations absent');
 // Operational failure includes original finally/cleanup and final report failures.
 // A scanner exit 1 is NOT this parent exit: it is retained in observations.
 let classification=null,classifierError=null,decision;
 if(Array.isArray(raw.classifierInput?.findings)&&raw.classifierInput.findings.length){
  try{classification=gitleaksEvidence(raw.classifierInput);}catch(e){classifierError=e.message;}
 }
 if(raw.execution.exitStatus!==0)decision='FAIL';
 else{
  const bytes=raw.reports['.devsecops/source-gate.json'];
  if(typeof bytes!=='string'||typeof raw.reports['.devsecops/gitleaks-native.json']!=='string'||!raw.classifierInput)return absent('Successful parent lacks native/classifier/report evidence');
  let report;try{report=JSON.parse(bytes);}catch{return absent('Successful parent report malformed');}
  if(report.status!=='success'||!isDeepStrictEqual(report.sourceScan?.findings,raw.classifierInput.findings))return absent('Successful original source/classifier identity inconsistent');
  // Original loop never touches review entries when there are zero findings.
  // Do not invent a new failure for an unused null entries field in that case.
  if(!Array.isArray(raw.classifierInput.findings))return absent('Original finding array absent');
  if(raw.classifierInput.findings.length){if(!classification)return absent('Successful parent lacks valid existing classifier facts');decision=classification.observations.some(x=>!x.reviewMatched)?'FAIL':'PASS';}
  else decision='PASS';
 }
 return {status:decision,decision,normalizedFacts:{execution:structuredClone(raw.execution),classification,classifierError,scannerExecutions:raw.observations.filter(x=>x.type==='command'&&x.key.startsWith('scan:')).map(x=>structuredClone(x)),aggregation:'Original complete parent process exit includes prerequisite, scanner/report and finally failures; existing classifier reused, no severity invented'},rawEvidence:structuredClone(raw)};
}
