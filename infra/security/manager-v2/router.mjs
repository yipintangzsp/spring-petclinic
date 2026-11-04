import {DEFINITION as DOJO,prepareDefectDojo,publishDefectDojo} from './consumers/defectdojo.mjs';
import fs from 'node:fs';import path from 'node:path';
import {keys,identity} from './config.mjs';import {artifactStore,verifyArtifact,verifyResult} from './result.mjs';
import {digest,freeze,fail} from '../summary-v2/codec.mjs';
export const CONSUMERS=freeze([
 {consumerId:'dry-run',enabled:true,requiredInputs:['SECURITY_SUMMARY'],inputSchema:'SecuritySummaryCandidate/v1',publish:'dry-run',verify:'digest/v1',errorPolicy:'RECORD_AND_BLOCK'},
 {consumerId:'local-evidence',enabled:true,requiredInputs:['SECURITY_SUMMARY'],inputSchema:'SecuritySummaryCandidate/v1',publish:'local-evidence',verify:'digest/v1',errorPolicy:'RECORD_AND_BLOCK'},
 {consumerId:'defectdojo-future',enabled:false,requiredInputs:['SECURITY_SUMMARY','DEFECTDOJO_API'],inputSchema:'SecuritySummaryCandidate/v1',publish:'future-adapter',verify:'digest/v1',errorPolicy:'RECORD_AND_BLOCK'}
]);
export function consumers(definitions=CONSUMERS){
 if(!Array.isArray(definitions))fail('consumer registry');const ids=new Set();
 for(const c of definitions){
  if(c.consumerId===DOJO.consumerId){keys(c,Object.keys(DOJO));const {enabled,...body}=c,{enabled:_,...expected}=DOJO;if(typeof enabled!=='boolean'||digest(body)!==digest(expected))fail('consumer contract');}
  else keys(c,Object.keys(CONSUMERS[0]));identity(c.consumerId);if(ids.has(c.consumerId))fail('duplicate consumer');ids.add(c.consumerId);
  if(typeof c.enabled!=='boolean'||!Array.isArray(c.requiredInputs)||!c.requiredInputs.every(k=>['SECURITY_SUMMARY','DEFECTDOJO_API','CANDIDATE_ARTIFACT'].includes(k))||c.inputSchema!=='SecuritySummaryCandidate/v1'||!['dry-run','local-evidence','future-adapter','defectdojo-dry-run'].includes(c.publish)||!['digest/v1','payload-digest/v1'].includes(c.verify)||c.publish==='defectdojo-dry-run'&&c.consumerId!==DOJO.consumerId||c.consumerId!==DOJO.consumerId&&(c.verify!=='digest/v1'||c.requiredInputs.includes('CANDIDATE_ARTIFACT'))||c.errorPolicy!=='RECORD_AND_BLOCK')fail('consumer contract');
 }
 return freeze(structuredClone(definitions));
}
export function routeResults({run,artifactDirectory,expectedSealDigest,output,definitions=CONSUMERS,consumerOptions={}}){
 verifyArtifact(artifactDirectory,expectedSealDigest);
 const summary=run.summary;
 if(digest(JSON.parse(fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json'))))!==digest(summary))fail('router summary integrity');
 if(summary.kind!=='SecuritySummaryCandidate'||summary.productionEvidence!==false||summary.promotion.status!=='BLOCKED')fail('not a candidate summary');
 summary.pluginResults.forEach(verifyResult);
 const resultDigests=Object.fromEntries(summary.pluginResults.map(r=>[r.pluginId,r.resultDigest]));
 keys(consumerOptions,[DOJO.consumerId]);
 const receipts=[];
 for(const c of consumers(definitions)){
  let deliveryDecision,receiptSeal=null,error=null,extension={};
  if(!c.enabled)deliveryDecision='DISABLED';
  else if(c.publish==='future-adapter')deliveryDecision='NOT_CONFIGURED';
  else if(c.publish==='dry-run')deliveryDecision='DRY_RUN';
  else if(c.publish==='defectdojo-dry-run'){
   try{const source=path.resolve(artifactDirectory),destination=path.resolve(output);if(destination===source||destination.startsWith(source+path.sep)){const e=Error('OUTPUT_OVERLAPS_INPUT_ARTIFACT');e.code='OUTPUT_OVERLAPS_INPUT_ARTIFACT';throw e;}const options=consumerOptions[DOJO.consumerId]??{};keys(options,['mode','destination','token']);const prepared=prepareDefectDojo({run,artifactDirectory,expectedSealDigest}),delivered=publishDefectDojo(prepared,{...options,output});({deliveryDecision,receiptSeal,error,...extension}=delivered);}
   catch(e){deliveryDecision='ERROR';error='DEFECTDOJO_PREPARATION_FAILED';extension={consumerVersion:DOJO.consumerVersion,diagnosticCode:/^[A-Z_]{3,70}$/.test(e.code??'')?e.code:'INVALID_INPUT_OR_PREPARATION',remoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED',httpRequestCount:0,historyActions:[]};}
  }
  else{
   try{
    const store=artifactStore(path.join(output,c.consumerId));store.put('delivered-candidate.json',summary);const seal=store.finish();
    verifyArtifact(store.directory,seal.sealDigest);receiptSeal=seal.sealDigest;deliveryDecision='DELIVERED_LOCAL_ONLY';
   }catch{deliveryDecision='ERROR';error='LOCAL_DELIVERY_FAILED';}
  }
  const body={schemaVersion:1,kind:'CandidateDeliveryReceipt',consumerId:c.consumerId,runId:summary.runId,projectId:summary.projectId,deliveryDecision,inputDigest:digest(summary),resultDigests,receiptSeal,error,productionDelivery:false,promotionAllowed:false,...extension};
  receipts.push(freeze({...body,receiptDigest:digest(body)}));
 }
 const blocked=receipts.some(r=>['ERROR','NOT_CONFIGURED'].includes(r.deliveryDecision));
 return freeze({receipts,deliveryStatus:blocked?'ERROR':'CANDIDATE_ONLY',candidateDeliveryAllowed:!blocked,productionDeliveryCount:0});
}
