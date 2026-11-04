import fs from 'node:fs';import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {classifyVulnerability} from '../trivy-medium-policy.mjs';
import {verifyTrivySourceLock} from './trivy-source-lock.mjs';
// Frozen execution facts and the unchanged classifier; no HTTP, DB updater or scanner.
export function trivyParent(raw){
 const {lock}=verifyTrivySourceLock();
 const absent=reason=>({status:'NOT_TESTED',decision:null,reason,rawEvidence:structuredClone(raw)});
 if(!raw||raw.schema!==1||raw.complete!==true)return absent('Complete original Trivy observations absent');
 if(raw.stage==='wrapper'){
  if(!Array.isArray(raw.observations)||typeof raw.execution?.failed!=='boolean')return absent('Original selected Manager execution absent');
  const decision=raw.execution.failed||raw.module?.status==='failed'?'FAIL':raw.module?.status==='success'?'PASS':null;
  return decision?{status:decision,decision,rawEvidence:structuredClone(raw)}:absent('Selected module result absent');
 }
 if(['release-scan','database-prerequisite'].includes(raw.stage)){
  if(!Number.isInteger(raw.execution?.exitStatus)||!Array.isArray(raw.observations))return absent('Existing stage execution observations absent');
  if(raw.execution.exitStatus===0){
   if(raw.stage==='release-scan'&&typeof raw.reports?.['target/platform/harbor.json']!=='string')return absent('Successful release scan lacks original report');
   if(raw.stage==='database-prerequisite'&&(!raw.metadataBefore||!raw.result?.metadata||!Array.isArray(raw.result.actions)))return absent('Successful DB prerequisite lacks original metadata/result');
  }
  const decision=raw.execution.exitStatus===0?'PASS':'FAIL';
  return {status:decision,decision,normalizedFacts:{execution:structuredClone(raw.execution),scope:raw.stage==='release-scan'?'Existing Harbor scan-completion Gate only; no added vulnerability severity gate':'Separate existing upstream database prerequisite; not imposed on audit command'},rawEvidence:structuredClone(raw)};
 }
 if(raw.stage!=='parent'||raw.command!==lock.command||!Array.isArray(raw.operations)||!raw.operations.length)return absent('Original combined parent receipt absent');
 const first=raw.operations[0];if(first.stage!=='ensure-candidate'||!Number.isInteger(first.execution?.exitStatus))return absent('Candidate prerequisite execution absent');
 if(first.execution.exitStatus===0){if(raw.operations.length!==2||raw.operations[1]?.stage!=='audit'||!Number.isInteger(raw.operations[1].execution?.exitStatus))return absent('Original && continuation observations absent');}
 else if(raw.operations.length!==1)return absent('Original && short circuit inconsistent');
 if(raw.operations.some(x=>!Array.isArray(x.observations)||!x.reports))return absent('Original command/report facts absent');
 const audit=raw.operations.find(x=>x.stage==='audit');let classifications=null,classifierError=null;
 if(audit?.classifierInput){try{classifications=audit.classifierInput.findings.map(v=>classifyVulnerability(v,audit.classifierInput.review,audit.classifierInput.image));}catch(e){classifierError=e.message;}}
 let decision=raw.operations.some(x=>x.execution.exitStatus!==0)?'FAIL':'PASS';
 if(decision==='PASS'){
  const bytes=audit.reports['.devsecops/trivy-audit.json'];if(typeof bytes!=='string'||!classifications)return absent('Successful original audit lacks complete report/classifier facts');
  let report;try{report=JSON.parse(bytes);}catch{return absent('Successful original report malformed');}
  if(report.status!=='success')return absent('Successful receipt conflicts with original report');
  let reportedFindings;try{reportedFindings=report.scans.flatMap(s=>Object.values(s.raw).flatMap(x=>x.vulnerabilities??[]));}catch{return absent('Successful original raw scan facts incomplete');}
  if(report.image!==audit.classifierInput.image||!isDeepStrictEqual(reportedFindings,audit.classifierInput.findings))return absent('Classifier facts do not match original report/image');
  if(classifications.some(x=>x.mode==='FAIL'))decision='FAIL';
 }
 return {status:decision,decision,normalizedFacts:{classifications,classifierError,scope:'Existing && parent. Nonblocking Medium/Low remain raw WARN while original whole stage can PASS; no new severity or DB rule'},rawEvidence:structuredClone(raw)};
}
