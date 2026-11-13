// Production-path fact envelope. No Policy import, decision or scanner invocation.
import fs from 'node:fs';
import {EXPECTED_SOURCES} from '../summary-v2/inventory.mjs';
import {digest,equal,fail,freeze,validateBinding} from '../summary-v2/codec.mjs';

export const SOURCE_MAPPING=Object.freeze({
  semgrep:'semgrep-command-audit',
  'security-approval-promotion':null // post-approval; never a pre-approval input
});
export function collectRuntimeFacts({sourceId,binding,execution,payload,reports=[],evidence=[],presence='executed'}) {
  validateBinding(binding);
  if(!EXPECTED_SOURCES.includes(sourceId))fail('noncanonical runtime source');
  if(!['executed','skipped','not_configured','error'].includes(presence))fail('runtime presence absent');
  if(!execution||!Number.isSafeInteger(execution.exitStatus)&&execution.exitStatus!==null||
    !Object.hasOwn(execution,'signal')||!Object.hasOwn(execution,'errorClass')||typeof execution.command!=='string')fail('execution observation incomplete');
  if(presence==='executed'&&execution.exitStatus===null&&!execution.signal&&!execution.errorClass)fail('execution not terminal');
  if(presence!=='executed'&&(typeof execution.reason!=='string'||!execution.reason))fail('nonexecution reason absent');
  if(!Array.isArray(evidence)||!Array.isArray(reports))fail('evidence identity list absent');
  for(const r of reports)if(typeof r.path!=='string'||!/^[a-f0-9]{64}$/.test(r.sha256)||!Number.isSafeInteger(r.bytes))fail('report identity malformed');
  const facts={component:sourceId,status:presence==='executed'?'success':presence==='error'?'error':presence,raw:structuredClone(payload)};
  const envelope={schema:1,kind:'RuntimeSourceFacts',sourceId,buildBinding:structuredClone(binding),execution:structuredClone(execution),presence,
    rawFactDigest:digest(facts),reports:structuredClone(reports),evidence:structuredClone(evidence),facts};
  return freeze({...envelope,envelopeDigest:digest(envelope)});
}
export function validateRuntimeFacts(envelope,binding){
  if(envelope?.kind!=='RuntimeSourceFacts'||envelope.schema!==1||!equal(envelope.buildBinding,binding))fail('stale runtime facts binding');
  const {envelopeDigest,...body}=envelope;
  if(digest(body)!==envelopeDigest||digest(body.facts)!==body.rawFactDigest)fail('runtime fact integrity');
  const rebuilt=collectRuntimeFacts({sourceId:body.sourceId,binding,execution:body.execution,payload:body.facts.raw,reports:body.reports,evidence:body.evidence,presence:body.presence});
  if(!equal(rebuilt,envelope))fail('malformed runtime facts');
  return rebuilt;
}
// Exact file bytes observed AFTER this invocation; caller supplies paths it owns.
// No directory crawling, Secret lookup or optimistic missing-report defaults.
export function reportIdentities(paths){
  return paths.map(path=>{const bytes=fs.readFileSync(path);return {path,bytes:bytes.length,sha256:digestBytes(bytes)};});
}
import crypto from 'node:crypto';
const digestBytes=b=>crypto.createHash('sha256').update(b).digest('hex');
