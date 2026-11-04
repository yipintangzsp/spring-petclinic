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
  keys(c,Object.keys(CONSUMERS[0]));identity(c.consumerId);if(ids.has(c.consumerId))fail('duplicate consumer');ids.add(c.consumerId);
  if(typeof c.enabled!=='boolean'||!Array.isArray(c.requiredInputs)||!c.requiredInputs.every(k=>['SECURITY_SUMMARY','DEFECTDOJO_API'].includes(k))||c.inputSchema!=='SecuritySummaryCandidate/v1'||!['dry-run','local-evidence','future-adapter'].includes(c.publish)||c.verify!=='digest/v1'||c.errorPolicy!=='RECORD_AND_BLOCK')fail('consumer contract');
 }
 return freeze(structuredClone(definitions));
}
export function routeResults({run,artifactDirectory,expectedSealDigest,output,definitions=CONSUMERS}){
 verifyArtifact(artifactDirectory,expectedSealDigest);
 const summary=run.summary;
 if(digest(JSON.parse(fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json'))))!==digest(summary))fail('router summary integrity');
 if(summary.kind!=='SecuritySummaryCandidate'||summary.productionEvidence!==false||summary.promotion.status!=='BLOCKED')fail('not a candidate summary');
 summary.pluginResults.forEach(verifyResult);
 const resultDigests=Object.fromEntries(summary.pluginResults.map(r=>[r.pluginId,r.resultDigest]));
 const receipts=[];
 for(const c of consumers(definitions)){
  let deliveryDecision,receiptSeal=null,error=null;
  if(!c.enabled)deliveryDecision='DISABLED';
  else if(c.publish==='future-adapter')deliveryDecision='NOT_CONFIGURED';
  else if(c.publish==='dry-run')deliveryDecision='DRY_RUN';
  else{
   try{
    const store=artifactStore(path.join(output,c.consumerId));store.put('delivered-candidate.json',summary);const seal=store.finish();
    verifyArtifact(store.directory,seal.sealDigest);receiptSeal=seal.sealDigest;deliveryDecision='DELIVERED_LOCAL_ONLY';
   }catch{deliveryDecision='ERROR';error='LOCAL_DELIVERY_FAILED';}
  }
  const body={schemaVersion:1,kind:'CandidateDeliveryReceipt',consumerId:c.consumerId,runId:summary.runId,projectId:summary.projectId,deliveryDecision,inputDigest:digest(summary),resultDigests,receiptSeal,error,productionDelivery:false,promotionAllowed:false};
  receipts.push(freeze({...body,receiptDigest:digest(body)}));
 }
 const blocked=receipts.some(r=>['ERROR','NOT_CONFIGURED'].includes(r.deliveryDecision));
 return freeze({receipts,deliveryStatus:blocked?'ERROR':'CANDIDATE_ONLY',candidateDeliveryAllowed:!blocked,productionDeliveryCount:0});
}
