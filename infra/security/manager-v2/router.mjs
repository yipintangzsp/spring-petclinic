import {createHttpTransport,deliverHttpCandidate,HTTP_CONSUMER} from './consumers/dojo-http.mjs';
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

// Explicit async Candidate extension; legacy routeResults/default registry remain
// synchronous/offline. A genuine transport handle is required to send HTTP.
export async function routeResultsHttp(options){
 keys(options,['run','artifactDirectory','expectedSealDigest','output','definitions','consumerOptions','transport','journalDirectory']);
 const {transport=createHttpTransport(),journalDirectory,...offlineOptions}=options;
 const offline=routeResults({...offlineOptions,definitions:options.definitions??[...CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future'),DOJO]});
 let httpDelivery;
 if(!offline.candidateDeliveryAllowed)httpDelivery={consumerId:HTTP_CONSUMER.consumerId,deliveryState:'NOT_SENT',redactedError:'OFFLINE_PREPARATION_BLOCKED',httpRequestCount:0,receipts:[],realRemoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED'};
 else try{httpDelivery=await deliverHttpCandidate({run:options.run,artifactDirectory:options.artifactDirectory,expectedSealDigest:options.expectedSealDigest,transport,journalDirectory});}
 catch(e){httpDelivery={consumerId:HTTP_CONSUMER.consumerId,deliveryState:'NOT_SENT',redactedError:/^[A-Z_]{3,80}$/.test(e.code??'')?e.code:'HTTP_CANDIDATE_REJECTED',httpRequestCount:0,receipts:[],realRemoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED'};}
 const blocked=!['ACKNOWLEDGED'].includes(httpDelivery.deliveryState)&&httpDelivery.redactedError!=='HTTP_DISABLED_BY_DEFAULT';
 return freeze({...offline,httpDelivery,deliveryStatus:blocked?'ERROR':offline.deliveryStatus,candidateDeliveryAllowed:!blocked&&offline.candidateDeliveryAllowed});
}

// Explicit Loki registration. Both existing routing entry points stay unchanged;
// the same verified Result is projected, never scanned or evaluated again.
export {LOKI_DEFINITION} from './consumers/loki.mjs';
import {prepareLoki,publishLoki,createLokiTransport,LOKI_DEFINITION} from './consumers/loki.mjs';
export async function routeResultsWithLoki(options){
 keys(options,['run','artifactDirectory','expectedSealDigest','output','definitions','consumerOptions','transport','journalDirectory','lokiTransport','lokiOutput','expectedProjectId','priorLokiReceipts','singlePluginId','freshRunId']);
 const {lokiTransport=createLokiTransport(),lokiOutput,expectedProjectId,priorLokiReceipts=[],singlePluginId=null,freshRunId=null,...base}=options;
 const offline=options.transport?await routeResultsHttp(base):routeResults(base);
 let lokiDelivery;
 try{
  const plan=prepareLoki({run:options.run,artifactDirectory:options.artifactDirectory,expectedSealDigest:options.expectedSealDigest,expectedProjectId,singlePluginId,freshRunId,deliveryReceipts:[...offline.receipts,...(offline.httpDelivery?.receipts??[]),...priorLokiReceipts]});
  lokiDelivery=await publishLoki(plan,{output:lokiOutput,transport:lokiTransport});
 }catch(e){
  const body={schemaVersion:1,kind:'LokiCandidateDeliveryReceipt',consumerId:LOKI_DEFINITION.consumerId,consumerVersion:LOKI_DEFINITION.consumerVersion,runId:options.run.summary.runId,projectId:options.run.summary.projectId,resultDigests:Object.fromEntries(options.run.summary.pluginResults.map(r=>[r.pluginId,r.resultDigest])),deliveryState:'ERROR',errorCategory:'LOKI_PREPARATION_OR_DELIVERY_FAILED',diagnosticCode:/^[A-Z_]{3,80}$/.test(e.code??'')?e.code:'INVALID_INPUT',timestamp:new Date().toISOString(),httpRequestCount:0,productionDelivery:false,promotionAllowed:false,realRemoteDelivery:'NOT_TESTED',remoteExactlyOnce:'NOT_VERIFIED'};
  lokiDelivery=freeze({...body,receiptDigest:digest(body)});
 }
 const ok=['ACKNOWLEDGED','DRY_RUN','DISABLED'].includes(lokiDelivery.deliveryState);
 return freeze({...offline,lokiDelivery,deliveryStatus:ok?offline.deliveryStatus:'ERROR',candidateDeliveryAllowed:ok&&offline.candidateDeliveryAllowed});
}
