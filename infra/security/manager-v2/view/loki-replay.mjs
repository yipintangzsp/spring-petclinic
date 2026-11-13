// Read-only audit projection. Never sends events, runs scanners or rewrites results.
import {canonical,digest} from '../../summary-v2/codec.mjs';
import {validateLokiEvent} from '../consumers/loki.mjs';
import {grafanaRunUrl} from './loki-delivery.mjs';
const requireValue=(ok,code)=>{if(!ok)throw Object.assign(Error(code),{code,status:503});};
const same=(a,b)=>digest(a)===digest(b);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const time=x=>typeof x==='string'&&Number.isFinite(Date.parse(x));
export function replayAuditEvent(result,receipt,queryProof){
 const body={schemaVersion:1,kind:'LokiReplayAuditEvent',runId:result.runId,projectId:result.projectId,
  pluginId:result.pluginId,resultDigest:result.resultDigest,artifactDigest:result.artifactDigest,receipt,queryProof};
 const event={...body,auditDigest:digest(body)};
 verifyReplayAuditEvent(event,result);return event;
}
export function verifyReplayAuditEvent(a,result){
 const {auditDigest,...body}=a;
 requireValue(same(Object.keys(body).sort(),['schemaVersion','kind','runId','projectId','pluginId','resultDigest','artifactDigest','receipt','queryProof'].sort())&&hex(auditDigest)&&digest(body)===auditDigest,'LOKI_REPLAY_AUDIT_INTEGRITY');
 requireValue(a.schemaVersion===1&&a.kind==='LokiReplayAuditEvent'&&result.state==='COMPLETED'&&result.evidenceClass==='REAL'&&result.evaluationCount===1,'LOKI_REPLAY_REAL_RESULT_REQUIRED');
 for(const key of ['runId','projectId','pluginId','resultDigest','artifactDigest'])requireValue(a[key]===result[key],'LOKI_REPLAY_RESULT_BINDING');
 const r=a.receipt,q=a.queryProof,{receiptDigest,...receiptBody}=r;
 requireValue(hex(receiptDigest)&&digest(receiptBody)===receiptDigest,'LOKI_REPLAY_RECEIPT_INTEGRITY');
 requireValue(r.kind==='LokiCandidateDeliveryReceipt'&&r.consumerId==='loki-candidate'&&r.mode==='real-http'&&r.targetIdentity==='existing-security-loki-v1'&&r.productionDelivery===true&&r.promotionAllowed===false&&r.deliveryState==='ACKNOWLEDGED'&&r.httpStatus===204&&r.httpRequestCount===1,'LOKI_REPLAY_RECEIPT_NOT_DELIVERED');
 requireValue(r.runId===a.runId&&r.projectId===a.projectId&&r.artifactDigest===a.artifactDigest&&r.resultDigests?.[a.pluginId]===a.resultDigest,'LOKI_REPLAY_RECEIPT_BINDING');
 requireValue(q.runId===a.runId&&q.projectId===a.projectId&&q.resultDigest===a.resultDigest&&q.policyDecision===result.policyDecision&&q.sourceClassification==='SEALED_ARTIFACT_REPLAY_NOT_NEW_SCAN'&&q.httpStatus===200&&q.eventCount===1&&q.events?.length===1,'LOKI_REPLAY_QUERY_BINDING');
 const e=q.events[0];validateLokiEvent(e);
 requireValue(e.runId===a.runId&&e.projectId===a.projectId&&e.pluginId===a.pluginId&&e.resultDigest===a.resultDigest&&e.artifactDigest===a.artifactDigest&&e.policyDecision===result.policyDecision&&e.evaluationCount===1&&e.executionStatus==='COMPLETED'&&e.sourceClassification===q.sourceClassification&&same(r.eventIdentities,[e.eventIdentity]),'LOKI_REPLAY_EVENT_BINDING');
 const payload={streams:[{stream:{service_name:'security-manager-v2',environment:'validation',schema_version:'1',job:'devsecops-security-v2',plugin:e.pluginId,execution_status:e.executionStatus,policy_decision:e.policyDecision},values:[[String(BigInt(Date.parse(e.timestamp))*1000000n),canonical(e)]]}]};
 requireValue(digest(payload)===r.payloadDigest&&r.attempts?.length===1&&r.attempts[0].httpStatus===204&&r.attempts[0].requestBodySha256===r.payloadDigest,'LOKI_REPLAY_PAYLOAD_BINDING');
 requireValue(time(r.timestamp)&&time(q.queriedAt)&&Date.parse(q.queriedAt)>=Date.parse(r.timestamp),'LOKI_REPLAY_TIME_BINDING');
 const grafanaUrl=grafanaRunUrl({...e,completedAt:e.timestamp});
 requireValue(q.grafanaUrl===grafanaUrl,'LOKI_REPLAY_GRAFANA_BINDING');
 // Expose only fixed, validated fields, not raw receipts or arbitrary diagnostics.
 return {kind:a.kind,automatic:false,state:'DELIVERED',sourceClassification:e.sourceClassification,
  runId:a.runId,projectId:a.projectId,pluginId:a.pluginId,resultDigest:a.resultDigest,
  policyDecision:e.policyDecision,receiptDigest,queryState:'VERIFIED',pushHttpStatus:204,
  queryHttpStatus:200,deliveryAt:r.timestamp,queryAt:q.queriedAt,findingCount:e.findingCount,
  nativeSeverityCounts:e.nativeSeverityCounts,grafanaUrl,auditDigest};
}
export function withReplayAudit(result,event){
 return {...result,lokiReplayEvents:[verifyReplayAuditEvent(event,result)]};
}
