// Versioned projection of immutable Candidate facts. No scanner or Policy owner.
import fs from 'node:fs';import path from 'node:path';import http from 'node:http';
import {canonical,digest,sha,freeze} from '../../summary-v2/codec.mjs';
import {verifyArtifact,verifyResult,artifactStore} from '../result.mjs';
export const LOKI_SCHEMA=freeze(JSON.parse(fs.readFileSync(new URL('./loki-event-v1.json',import.meta.url))));
export const LOKI_DEFINITION=freeze({consumerId:'loki-candidate',consumerVersion:LOKI_SCHEMA.consumerVersion,enabled:true,defaultMode:'dry-run',requiredInputs:['CANDIDATE_ARTIFACT','SECURITY_SUMMARY'],supportedSchemaVersions:[1],publish:'loki-json-push-candidate',errorPolicy:'RECORD_AND_BLOCK',realDeliveryApproved:false});
const plans=new WeakMap(),transports=new WeakMap(),same=(a,b)=>canonical(a)===canonical(b);
const must=(yes,code)=>{if(!yes){const e=Error(code);e.code=code;throw e;}};
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const secret=/(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN .*PRIVATE KEY-----|Bearer\s+\S+|Authorization\s*[:=]|\b(?:password|api_token|access_token)\s*[:=]|SMV2_MOCK_TOKEN_[A-Za-z0-9_]+)/i;
const identity=x=>{must(typeof x==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$/.test(x)&&!secret.test(x),'UNSAFE_EVENT_IDENTITY');return x;};
const version=x=>{must(typeof x==='string'&&/^\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.-]{1,60})?$/.test(x),'UNSAFE_EVENT_VERSION');return x;};
const objectKeys=(x,keys)=>must(x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).every(k=>keys.includes(k)),'UNEXPECTED_LOKI_FIELD');
const iso=x=>{must(typeof x==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x,'EVENT_TIMESTAMP_INVALID');return x;};
const ns=x=>String(BigInt(Date.parse(iso(x)))*1000000n);
function eventId(e){return digest({schemaVersion:e.schemaVersion,eventType:e.eventType,runId:e.runId,projectId:e.projectId,pluginId:e.pluginId,resultDigest:e.resultDigest,summaryDigest:e.summaryDigest,consumerId:e.consumerId,sourceReceiptDigest:e.sourceReceiptDigest});}
const safeError=r=>r.executionStatus==='POLICY_ERROR'?'POLICY_ERROR':r.executionStatus==='ERROR'?'EXECUTION_ERROR':['NOT_CONFIGURED','UNSUPPORTED'].includes(r.executionStatus)?'CAPABILITY_UNAVAILABLE':r.executionStatus==='SKIPPED'?'EXECUTION_SKIPPED':r.executionStatus==='DISABLED'?['MASTER_DISABLED','MODE_OFF','PLUGIN_DISABLED'].includes(r.failureReason)?r.failureReason:'PLUGIN_DISABLED':null;
function counts(dir,seal,r){
 const empty={findingCount:null,findingCountKnown:false,highSeverityFindingCount:null,highSeverityCountKnown:false,nativeSeverityCounts:null,findingEvidenceStatus:'NOT_EXECUTED'};
 if(r.executionStatus!=='COMPLETED')return empty;
 if(['cosign','sbom'].includes(r.pluginId))return {...empty,findingEvidenceStatus:'NOT_A_VULNERABILITY_SCANNER'};
 if(!['gitleaks','semgrep'].includes(r.pluginId))return {...empty,findingEvidenceStatus:'COUNT_MAPPING_NOT_CONFIGURED'};
 const name=r.pluginId+'.facts.json';if(!seal.files[name])return {...empty,findingEvidenceStatus:'FACT_NOT_AVAILABLE'};
 const p=path.join(dir,name),s=fs.lstatSync(p);must(s.isFile()&&!s.isSymbolicLink()&&s.size<=2*1024*1024,'FACT_READ_BOUNDARY');
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let fact;try{const stat=fs.fstatSync(fd);must(stat.isFile()&&stat.size<=2*1024*1024,'FACT_READ_BOUNDARY');fact=JSON.parse(fs.readFileSync(fd));}finally{fs.closeSync(fd);}must(digest(fact)===r.factDigest&&fact.component===r.pluginId,'FACT_RESULT_BINDING');
 if(fact.status!=='success'||!Array.isArray(fact.raw?.findings))return {...empty,findingEvidenceStatus:'FACT_NOT_COMPLETE'};
 const findings=fact.raw.findings;must(findings.length<=10000,'FINDING_COUNT_LIMIT');
 if(r.pluginId==='gitleaks')return {...empty,findingCount:findings.length,findingCountKnown:true,findingEvidenceStatus:'VERIFIED_NATIVE_COUNT_NO_NATIVE_SEVERITY'};
 const severities={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0,ERROR:0,WARNING:0,UNKNOWN:0};
 for(const f of findings){const sev=typeof f.extra?.severity==='string'?f.extra.severity.toUpperCase():'UNKNOWN';severities[Object.hasOwn(severities,sev)?sev:'UNKNOWN']++;}
 // ERROR/WARNING are retained as native rule severities, never silently renamed HIGH/MEDIUM.
 const known=severities.ERROR+severities.WARNING+severities.UNKNOWN===0;
 return {...empty,findingCount:findings.length,findingCountKnown:true,nativeSeverityCounts:severities,highSeverityFindingCount:known?severities.CRITICAL+severities.HIGH:null,highSeverityCountKnown:known,findingEvidenceStatus:'VERIFIED_NATIVE_COUNT'};
}
function labels(e){return {service_name:'security-manager-v2',environment:'validation',schema_version:'1',job:'devsecops-security-v2',plugin:e.pluginId,execution_status:e.executionStatus??'NOT_APPLICABLE',policy_decision:e.policyDecision??'NONE'};}
const eventFields=['schemaVersion','eventType','timestamp','timestampBasis','runId','projectId','profile','managerVersion','pluginId','pluginVersion','executionStatus','policyDecision','policyVersion','factDigest','resultDigest','artifactDigest','summaryDigest','evidenceRef','deliveryStatus','errorCategory','sourceClassification','productionEvidence','securityEnabled','globalMode','evaluationCount','promotionStatus','consumerId','sourceReceiptDigest','deliveryOrigin','findingCount','findingCountKnown','highSeverityFindingCount','highSeverityCountKnown','nativeSeverityCounts','findingEvidenceStatus','eventIdentity'];
export function validateLokiEvent(e){
 must(same(Object.keys(e).sort(),[...eventFields].sort())&&e.schemaVersion===1&&LOKI_SCHEMA.eventTypes.includes(e.eventType),'EVENT_SCHEMA');
 iso(e.timestamp);identity(e.runId);identity(e.projectId);identity(e.profile);version(e.managerVersion);if(e.pluginVersion!==null)version(e.pluginVersion);
 must(LOKI_SCHEMA.plugins.includes(e.pluginId)&&(e.executionStatus===null||LOKI_SCHEMA.executionStatuses.includes(e.executionStatus))&&(e.policyDecision===null||LOKI_SCHEMA.policyDecisions.includes(e.policyDecision)),'EVENT_STATUS');
 must(e.policyVersion==='baseline-v1'&&hex(e.artifactDigest)&&hex(e.summaryDigest)&&[e.factDigest,e.resultDigest,e.sourceReceiptDigest].every(x=>x===null||hex(x)),'EVENT_DIGEST_OR_POLICY');
 must(typeof e.securityEnabled==='boolean'&&['audit','off','enforce'].includes(e.globalMode)&&[0,1].includes(e.evaluationCount)&&e.productionEvidence===false&&e.promotionStatus==='BLOCKED'&&['SEALED_ARTIFACT_REPLAY_NOT_NEW_SCAN','REAL_CONTROLLED_EXECUTION'].includes(e.sourceClassification),'EVENT_SCOPE');
 must(LOKI_SCHEMA.deliveryStatuses.includes(e.deliveryStatus)&&(e.errorCategory===null||LOKI_SCHEMA.errorCategories.includes(e.errorCategory))&&['PREPARATION','LOCAL_ONLY','DRY_RUN','MOCK_HTTP','UNKNOWN'].includes(e.deliveryOrigin),'EVENT_DELIVERY');
 must(e.consumerId===null||['dry-run','local-evidence','defectdojo-candidate','defectdojo-http-candidate','defectdojo-future','loki-candidate'].includes(e.consumerId),'EVENT_CONSUMER');
 must(e.eventIdentity===eventId(e)&&Array.isArray(e.evidenceRef)&&e.evidenceRef.length<=3&&e.evidenceRef.every(r=>same(Object.keys(r).sort(),['digest','kind'])&&['RESULT','FACT','SUMMARY'].includes(r.kind)&&hex(r.digest)),'EVENT_REFERENCE');
 for(const [n,k]of [['findingCount','findingCountKnown'],['highSeverityFindingCount','highSeverityCountKnown']])must(typeof e[k]==='boolean'&&(e[k]?Number.isInteger(e[n])&&e[n]>=0&&e[n]<=10000:e[n]===null),'UNKNOWN_FINDINGS_NOT_ZERO');
 must(['RESULT_COMPLETED_AT','SOURCE_RECEIPT_TIMESTAMP','RESULT_COMPLETION_RECEIPT_TIME_UNAVAILABLE','LAST_RESULT_COMPLETED_AT'].includes(e.timestampBasis)&&['NOT_EXECUTED','NOT_A_VULNERABILITY_SCANNER','COUNT_MAPPING_NOT_CONFIGURED','FACT_NOT_AVAILABLE','FACT_NOT_COMPLETE','VERIFIED_NATIVE_COUNT_NO_NATIVE_SEVERITY','VERIFIED_NATIVE_COUNT','NOT_APPLICABLE'].includes(e.findingEvidenceStatus),'EVENT_EVIDENCE_ENUM');
 if(e.nativeSeverityCounts!==null){must(same(Object.keys(e.nativeSeverityCounts).sort(),['CRITICAL','HIGH','MEDIUM','LOW','INFO','ERROR','WARNING','UNKNOWN'].sort())&&Object.values(e.nativeSeverityCounts).every(n=>Number.isInteger(n)&&n>=0&&n<=10000)&&Object.values(e.nativeSeverityCounts).reduce((a,b)=>a+b,0)===e.findingCount,'NATIVE_SEVERITY_SCHEMA');}
 if(e.eventType==='PROMOTION_STATUS')must(e.pluginId==='manager'&&e.executionStatus===null&&e.policyDecision===null&&e.resultDigest===null&&!e.findingCountKnown,'PROMOTION_EVENT_BINDING');
 else must(e.pluginId!=='manager'&&e.executionStatus!==null&&hex(e.resultDigest)&&(e.executionStatus==='COMPLETED'?e.evaluationCount===1&&e.policyDecision!==null:[0,1].includes(e.evaluationCount)&&e.policyDecision===null),'PLUGIN_EVENT_BINDING');
 if(e.eventType==='CONSUMER_DELIVERY')must(e.consumerId!==null&&hex(e.sourceReceiptDigest),'DELIVERY_EVENT_BINDING');
 if(e.eventType==='PLUGIN_RESULT'&&e.executionStatus!=='COMPLETED')must(e.policyDecision===null&&!e.findingCountKnown&&!e.highSeverityCountKnown,'NONEXECUTION_NOT_PASS');
 if(e.pluginId==='cosign')must(!e.findingCountKnown&&!e.highSeverityCountKnown,'COSIGN_NOT_CVE_COUNT');
 must(!secret.test(canonical(e))&&Buffer.byteLength(canonical(e))<=LOKI_SCHEMA.limits.maxLineBytes,'EVENT_REDACTION_OR_SIZE');return true;
}
function receiptForSource(receipt,summary){
 const {receiptDigest,...body}=receipt;must(hex(receiptDigest)&&digest(body)===receiptDigest&&receipt.runId===summary.runId&&receipt.projectId===summary.projectId&&receipt.productionDelivery===false,'DELIVERY_RECEIPT_BINDING');
 must(['CandidateDeliveryReceipt','DefectDojoHttpDeliveryReceipt','LokiCandidateDeliveryReceipt'].includes(receipt.kind),'UNSUPPORTED_DELIVERY_RECEIPT');
 for(const r of summary.pluginResults){if(receipt.resultDigests)must(receipt.resultDigests[r.pluginId]===r.resultDigest,'DELIVERY_RESULT_BINDING');}
 const status=receipt.deliveryState??receipt.deliveryDecision;must(LOKI_SCHEMA.deliveryStatuses.includes(status),'DELIVERY_STATUS_UNSUPPORTED');
 const consumerId=receipt.consumerId;must(['dry-run','local-evidence','defectdojo-candidate','defectdojo-http-candidate','defectdojo-future','loki-candidate'].includes(consumerId),'DELIVERY_CONSUMER_UNSUPPORTED');
 let origin=receipt.kind==='DefectDojoHttpDeliveryReceipt'?'MOCK_HTTP':receipt.kind==='LokiCandidateDeliveryReceipt'?receipt.mode==='mock-http'?'MOCK_HTTP':receipt.mode==='dry-run'?'DRY_RUN':'UNKNOWN':['DRY_RUN','OFFLINE_PAYLOAD_PREPARED'].includes(status)?'DRY_RUN':'LOCAL_ONLY';
 return {status,consumerId,origin,receiptDigest,timestamp:receipt.timestamp??null,pluginId:receipt.pluginId??null,resultDigest:receipt.resultDigest??null};
}
export function prepareLoki({run,artifactDirectory,expectedSealDigest,expectedProjectId,deliveryReceipts=[],singlePluginId=null,freshRunId=null}){
 const dir=path.resolve(artifactDirectory);must(fs.realpathSync(dir)===dir,'ARTIFACT_DIRECTORY_BOUNDARY');verifyArtifact(dir,expectedSealDigest);
 const summary=run.summary,seal=JSON.parse(fs.readFileSync(path.join(dir,'candidate-seal.json')));must(same(summary,JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json'))))&&summary.kind==='SecuritySummaryCandidate'&&summary.productionEvidence===false&&summary.promotion?.status==='BLOCKED','CANDIDATE_SUMMARY_BINDING');
 identity(summary.projectId);identity(summary.runId);identity(summary.profile);version(summary.managerVersion);must(summary.projectId===expectedProjectId,'LOKI_PROJECT_MISMATCH');must(Array.isArray(deliveryReceipts)&&deliveryReceipts.length<=12,'DELIVERY_RECEIPT_LIMIT');
 const ids=new Set();for(const r of summary.pluginResults){verifyResult(r);must(r.projectId===summary.projectId&&r.runId===summary.runId&&!ids.has(r.pluginId),'RESULT_SCOPE_BINDING');ids.add(r.pluginId);}
 must(singlePluginId===null||['gitleaks','semgrep','cosign','sbom'].includes(singlePluginId),'LOKI_PLUGIN_SELECTION_REJECTED');
 must(freshRunId===null||freshRunId===summary.runId&&singlePluginId!==null,'LOKI_FRESH_RUN_BINDING');
 const chosen=summary.pluginResults.filter(r=>(singlePluginId===null||r.pluginId===singlePluginId)&&LOKI_SCHEMA.plugins.includes(r.pluginId)&&r.pluginId!=='manager');must(chosen.length>0,'NO_OBSERVABLE_PLUGIN');
 if(freshRunId!==null)must(chosen.every(r=>r.executionStatus==='COMPLETED'&&r.runtimeFacts?.classification==='REAL_CONTROLLED_EXECUTION'&&r.runtimeFacts.validationRunId===freshRunId&&Date.now()-Date.parse(r.completedAt)>=0&&Date.now()-Date.parse(r.completedAt)<300000),'LOKI_FRESH_EXECUTION_EVIDENCE_REQUIRED');
 const end=chosen.map(r=>iso(r.completedAt)).sort().at(-1),summaryDigest=digest(summary),events=[];
 function make(r,eventType='PLUGIN_RESULT',extra={}){
  must(r.securityEnabled===summary.securityEnabled&&r.globalMode===summary.globalMode&&r.managerVersion===summary.managerVersion,'RESULT_CONFIGURATION_BINDING');
  const e={schemaVersion:1,eventType,timestamp:iso(r.completedAt),timestampBasis:'RESULT_COMPLETED_AT',runId:summary.runId,projectId:summary.projectId,profile:summary.profile,managerVersion:summary.managerVersion,pluginId:r.pluginId,pluginVersion:r.pluginVersion,executionStatus:r.executionStatus,policyDecision:r.policyDecision,policyVersion:r.policyVersion,factDigest:r.factDigest,resultDigest:r.resultDigest,artifactDigest:expectedSealDigest,summaryDigest,evidenceRef:[{kind:'RESULT',digest:r.resultDigest},...(r.factDigest?[{kind:'FACT',digest:r.factDigest}]:[])],deliveryStatus:'PREPARED',errorCategory:safeError(r),sourceClassification:freshRunId?'REAL_CONTROLLED_EXECUTION':'SEALED_ARTIFACT_REPLAY_NOT_NEW_SCAN',productionEvidence:false,securityEnabled:summary.securityEnabled,globalMode:summary.globalMode,evaluationCount:r.evaluationCount,promotionStatus:summary.promotion.status,consumerId:null,sourceReceiptDigest:null,deliveryOrigin:'PREPARATION',...counts(dir,seal,r),...extra};e.eventIdentity=eventId(e);validateLokiEvent(e);return e;
 }
 for(const r of chosen)events.push(make(r));
 for(const receipt of deliveryReceipts){const c=receiptForSource(receipt,summary);
  const selected=c.pluginId?chosen.filter(r=>r.pluginId===c.pluginId):chosen;
  must(!c.pluginId||selected.length===1&&selected[0].resultDigest===c.resultDigest,'DELIVERY_PLUGIN_RESULT_BINDING');
  for(const r of selected)events.push(make(r,'CONSUMER_DELIVERY',{timestamp:c.timestamp?iso(c.timestamp):r.completedAt,timestampBasis:c.timestamp?'SOURCE_RECEIPT_TIMESTAMP':'RESULT_COMPLETION_RECEIPT_TIME_UNAVAILABLE',deliveryStatus:c.status,errorCategory:['ERROR','REJECTED','RETRYABLE_FAILURE','UNKNOWN_REMOTE_STATE','DISABLED'].includes(c.status)?({ERROR:'CONSUMER_ERROR',REJECTED:'DELIVERY_REJECTED',RETRYABLE_FAILURE:'DELIVERY_RETRYABLE',UNKNOWN_REMOTE_STATE:'DELIVERY_UNKNOWN',DISABLED:'CONSUMER_DISABLED'})[c.status]:null,consumerId:c.consumerId,sourceReceiptDigest:c.receiptDigest,deliveryOrigin:c.origin}));
 }
 const manager={...make(chosen[0]),eventType:'PROMOTION_STATUS',timestamp:end,timestampBasis:'LAST_RESULT_COMPLETED_AT',pluginId:'manager',pluginVersion:null,executionStatus:null,policyDecision:null,factDigest:null,resultDigest:null,evaluationCount:0,evidenceRef:[{kind:'SUMMARY',digest:summaryDigest}],errorCategory:null,findingCount:null,findingCountKnown:false,highSeverityFindingCount:null,highSeverityCountKnown:false,nativeSeverityCounts:null,findingEvidenceStatus:'NOT_APPLICABLE'};manager.eventIdentity=eventId(manager);validateLokiEvent(manager);if(singlePluginId===null)events.push(manager);
 const unique=new Map();for(const e of events){if(unique.has(e.eventIdentity))must(same(unique.get(e.eventIdentity),e),'EVENT_IDENTITY_COLLISION');else unique.set(e.eventIdentity,e);}
 const final=[...unique.values()].sort((a,b)=>a.timestamp.localeCompare(b.timestamp)||a.eventIdentity.localeCompare(b.eventIdentity));must(final.length<=LOKI_SCHEMA.limits.maxEvents,'EVENT_BATCH_LIMIT');
 const streams=new Map();for(const e of final){const stream=labels(e),key=canonical(stream);if(!streams.has(key))streams.set(key,{stream,values:[]});streams.get(key).values.push([ns(e.timestamp),canonical(e)]);}
 const payload={streams:[...streams.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([,v])=>v)};validateLokiPush(payload);
 const body={schemaVersion:1,kind:'LokiCandidatePlan',projectId:summary.projectId,runId:summary.runId,summaryDigest,artifactDigest:expectedSealDigest,resultDigests:Object.fromEntries(summary.pluginResults.map(r=>[r.pluginId,r.resultDigest])),events:final,payload,payloadDigest:digest(payload),realRemoteDelivery:'NOT_TESTED',remoteExactlyOnce:'NOT_VERIFIED'};
 const plan=freeze({...body,planDigest:digest(body)});plans.set(plan,dir);return plan;
}
export function validateLokiPush(payload,{nowMs=null}={}){
 must(same(Object.keys(payload??{}),['streams'])&&Array.isArray(payload.streams)&&payload.streams.length>0&&payload.streams.length<=LOKI_SCHEMA.limits.maxStreams,'LOKI_PUSH_SCHEMA');let count=0;const seen=new Set();
 for(const s of payload.streams){must(same(Object.keys(s).sort(),['stream','values'])&&same(Object.keys(s.stream).sort(),[...LOKI_SCHEMA.labelKeys].sort())&&Array.isArray(s.values)&&s.values.length>0,'LOKI_LABEL_SCHEMA');let prior=0n;
  for(const v of s.values){must(Array.isArray(v)&&v.length===2&&typeof v[0]==='string'&&/^[1-9][0-9]{18}$/.test(v[0])&&typeof v[1]==='string','LOKI_ENTRY_SCHEMA');const e=JSON.parse(v[1]);validateLokiEvent(e);must(same(s.stream,labels(e))&&v[0]===ns(e.timestamp)&&BigInt(v[0])>=prior&&!seen.has(e.eventIdentity),'LOKI_ENTRY_BINDING_OR_DUPLICATE');prior=BigInt(v[0]);seen.add(e.eventIdentity);count++;
   if(nowMs!==null)must(Number.isFinite(nowMs)&&Date.parse(e.timestamp)>=nowMs-LOKI_SCHEMA.limits.maxAgeSeconds*1000&&Date.parse(e.timestamp)<=nowMs+LOKI_SCHEMA.limits.maxFutureSeconds*1000,'LOKI_TIMESTAMP_OUTSIDE_WINDOW');
  }
 }
 must(count<=LOKI_SCHEMA.limits.maxEvents&&Buffer.byteLength(canonical(payload))<=LOKI_SCHEMA.limits.maxBatchBytes,'LOKI_BATCH_SIZE');return true;
}
export function createLokiTransport(options={}){
 objectKeys(options,['mode','enabled','targetId','timeoutMs','maxAttempts','backoffMs']);const {mode='dry-run',enabled=true,targetId=null,timeoutMs=1000,maxAttempts=3,backoffMs=25}=options;
 must(typeof enabled==='boolean'&&['dry-run','mock-http','real-http'].includes(mode),'LOKI_MODE_INVALID');
 if(mode==='mock-http')must(targetId==='loki-loopback-v1','LOKI_TARGET_NOT_ALLOWLISTED');else if(mode==='real-http')must(targetId==='existing-security-loki-v1','LOKI_TARGET_NOT_ALLOWLISTED');else must(targetId===null,'LOKI_TARGET_NOT_ALLOWLISTED');
 must(Number.isInteger(timeoutMs)&&timeoutMs>=20&&timeoutMs<=5000&&Number.isInteger(maxAttempts)&&maxAttempts>=1&&maxAttempts<=3&&Number.isInteger(backoffMs)&&backoffMs>=1&&backoffMs<=1000,'LOKI_HTTP_BUDGET');
 const t=freeze({kind:'LokiCandidateTransport',enabled,mode});transports.set(t,{mode,enabled,targetId,timeoutMs,maxAttempts,backoffMs});return t;
}
function push(bytes,state){return new Promise(resolve=>{
 let connected=false,done=false,size=0;const finish=r=>{if(!done){done=true;clearTimeout(timer);resolve(r);}};
 const req=http.request({hostname:'127.0.0.1',port:state.mode==='real-http'?32189:32187,path:'/loki/api/v1/push',method:'POST',agent:false,maxHeaderSize:8192,headers:{'Content-Type':'application/json','Content-Length':bytes.length}},res=>{
  res.on('data',b=>{size+=b.length;if(size>8192){finish({status:res.statusCode,error:'RESPONSE_TOO_LARGE',connected});res.destroy();}});
  res.on('aborted',()=>finish({status:res.statusCode,error:'RESPONSE_LOST',connected}));res.on('error',()=>finish({status:res.statusCode,error:'RESPONSE_LOST',connected}));res.on('end',()=>finish({status:res.statusCode,error:null,connected}));
 });const timer=setTimeout(()=>{finish({status:null,error:'TIMEOUT',connected});req.destroy();},state.timeoutMs);
 req.on('socket',s=>s.once('connect',()=>connected=true));req.on('error',e=>finish({status:null,error:e.code==='ECONNREFUSED'?'CONNECTION_REFUSED':'CONNECTION_FAILED',connected}));req.end(bytes);
});}
export async function publishLoki(plan,{output,transport=createLokiTransport()}={}){
 must(plans.has(plan),'TRUSTED_LOKI_PLAN_REQUIRED');const state=transports.get(transport);must(state,'TRUSTED_LOKI_TRANSPORT_REQUIRED');validateLokiPush(plan.payload);
 const common={schemaVersion:1,kind:'LokiCandidateDeliveryReceipt',consumerId:LOKI_DEFINITION.consumerId,consumerVersion:LOKI_DEFINITION.consumerVersion,runId:plan.runId,projectId:plan.projectId,resultDigests:plan.resultDigests,artifactDigest:plan.artifactDigest,planDigest:plan.planDigest,payloadDigest:plan.payloadDigest,eventIdentities:plan.events.map(e=>e.eventIdentity),mode:state.mode,targetIdentity:state.mode==='real-http'?'existing-security-loki-v1':state.mode==='mock-http'?'loki-loopback-v1':'LOCAL_ONLY',timestamp:new Date().toISOString(),productionDelivery:state.mode==='real-http',realRemoteDelivery:'NOT_TESTED',remoteExactlyOnce:'NOT_VERIFIED',promotionAllowed:false};
 function receipt(deliveryState,extra={}){const b={...common,deliveryState,httpStatus:null,errorCategory:null,attempts:[],possibleDuplicates:false,httpRequestCount:0,...extra};return freeze({...b,receiptDigest:digest(b)});}
 if(!state.enabled)return receipt('DISABLED');
 must(typeof output==='string'&&path.isAbsolute(output)&&fs.realpathSync(output)===output,'LOKI_OUTPUT_BOUNDARY');
 const source=plans.get(plan);must(output!==source&&!output.startsWith(source+path.sep)&&!source.startsWith(output+path.sep),'LOKI_OUTPUT_OVERLAPS_ARTIFACT');
 const s=fs.statSync(output);must(s.isDirectory()&&s.uid===process.getuid()&&(s.mode&0o077)===0,'LOKI_OUTPUT_OWNERSHIP');
 const target=path.join(output,'loki-'+plan.planDigest);let payloadSeal;
 if(fs.existsSync(target))must(fs.lstatSync(target).isDirectory()&&!fs.lstatSync(target).isSymbolicLink()&&fs.realpathSync(target)===target,'LOKI_RETRY_DIRECTORY_BOUNDARY');
 if(fs.existsSync(target)){const seal=JSON.parse(fs.readFileSync(path.join(target,'candidate-seal.json')));verifyArtifact(target,digest(seal));must(same(JSON.parse(fs.readFileSync(path.join(target,'loki-plan.json'))),plan),'LOKI_RETRY_INPUT_CONFLICT');payloadSeal=digest(seal);}
 else{const store=artifactStore(target);store.put('loki-plan.json',plan);store.put('loki-push.json',plan.payload);payloadSeal=store.finish().sealDigest;}
 if(state.mode==='dry-run')return receipt('DRY_RUN',{payloadSeal});
 validateLokiPush(plan.payload,{nowMs:Date.now()});const bytes=Buffer.from(canonical(plan.payload)),attempts=[];let last;
 for(let n=1;n<=state.maxAttempts;n++){
  const r=await push(bytes,state);last=r;const status=r.status,ack=status===204&&!r.error;
  const retryable=[429,500,502,503,504].includes(status)||!r.connected&&r.error==='CONNECTION_REFUSED';
  const deliveryState=ack?'ACKNOWLEDGED':retryable?'RETRYABLE_FAILURE':r.error||status>=200&&status<300?'UNKNOWN_REMOTE_STATE':'REJECTED';
  attempts.push({attempt:n,httpStatus:status,deliveryState,errorCategory:r.error??(ack?null:retryable?'HTTP_RETRYABLE':'HTTP_REJECTED'),timestamp:new Date().toISOString(),requestBodySha256:sha(bytes)});
  if(ack)return receipt('ACKNOWLEDGED',{realRemoteDelivery:state.mode==='real-http'?'ACKNOWLEDGED_QUERY_NOT_VERIFIED':'NOT_TESTED',httpStatus:status,payloadSeal,attempts,possibleDuplicates:n>1,httpRequestCount:n});
  if(!retryable||n===state.maxAttempts)return receipt(deliveryState,{httpStatus:status,errorCategory:r.error??(retryable?'HTTP_RETRYABLE':'HTTP_REJECTED'),payloadSeal,attempts,possibleDuplicates:n>1||r.connected&&(status>=500||Boolean(r.error)),httpRequestCount:n});
  await new Promise(resolve=>setTimeout(resolve,Math.min(state.backoffMs*2**(n-1),1000)));
 }
 return receipt('UNKNOWN_REMOTE_STATE',{httpStatus:last?.status??null,attempts,httpRequestCount:attempts.length});
}
