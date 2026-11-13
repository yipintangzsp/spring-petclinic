// The sole non-release pipeline evaluator. Raw facts stay in memory; only safe
// envelopes' digests and resolved receipts are persisted. Claim before Engine.
import fs from 'node:fs';
import path from 'node:path';
import {createSourceOwner} from '../summary-v2/owner.mjs';
import {EXPECTED_SOURCES} from '../summary-v2/inventory.mjs';
import {gateView} from '../summary-v2/results.mjs';
import {digest,fail,freeze,validateBinding} from '../summary-v2/codec.mjs';
import {validateRuntimeFacts} from './collector.mjs';

export function createRuntimeOwner({binding,directory,config={}}){
  validateBinding(binding);
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  // Atomic exclusive run claim rejects a second process before any evaluation.
  const descriptor=fs.openSync(path.join(directory,'owner-claim.json'),'wx',0o600);
  fs.writeFileSync(descriptor,JSON.stringify({binding,owner:'runtime-facts/owner.mjs:createRuntimeOwner',pid:process.pid}));fs.closeSync(descriptor);
  const owner=createSourceOwner(binding),seen=new Map(),gate=new Map();
  const persist=(name,value)=>fs.writeFileSync(path.join(directory,name),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o400});
  return Object.freeze({
    async accept(envelope){
      const captured=validateRuntimeFacts(envelope,binding),id=captured.sourceId;
      // Per-source disk claim additionally survives process failure. A partial
      // owner cannot resume by silently evaluating a second time.
      const fd=fs.openSync(path.join(directory,id+'.claim'),'wx',0o600);fs.closeSync(fd);
      const r=await owner.evaluateOnce(id,captured.facts,config);
      if(r.rawFactDigest!==captured.rawFactDigest)fail('owner input identity changed');
      seen.set(id,r);
      persist(id+'.result.json',r);
      persist(id+'.capture.json',{schema:captured.schema,kind:captured.kind,sourceId:id,buildBinding:binding,presence:captured.presence,
        execution:captured.execution,rawFactDigest:captured.rawFactDigest,envelopeDigest:captured.envelopeDigest,reports:captured.reports,evidence:captured.evidence,
        rawPayloadPersisted:false,resultDigest:r.resultDigest,evaluationCount:owner.counts()[id],evidenceComplete:r.evidenceComplete});
      return r;
    },
    reuseForGate(sourceId,observedStatus){
      if(gate.has(sourceId))fail('duplicate Gate source handoff');
      if(!['success','failed','warn','skipped','disabled','not_configured'].includes(observedStatus))fail('legacy Gate observation missing');
      const r=owner.get(sourceId),view=gateView(r,binding);
      const expected=observedStatus==='failed'?'FAIL':observedStatus==='warn'?'WARN':observedStatus==='success'?'PASS':null;
      if(!r.evidenceComplete||r.error||view.decision!==expected)fail('Gate/Policy drift or incomplete evidence: '+sourceId);
      const value=freeze({...view,observedStatus});gate.set(sourceId,value);persist(sourceId+'.gate.json',value);return value;
    },
    snapshot(){return freeze({binding,canonicalSources:[...EXPECTED_SOURCES],missing:EXPECTED_SOURCES.filter(s=>!seen.has(s)),
      evaluationCounts:owner.counts(),sources:[...seen.values()],gate:Object.fromEntries(gate),
      complete:seen.size===EXPECTED_SOURCES.length&&gate.size===EXPECTED_SOURCES.length&&[...seen.values()].every(r=>r.evidenceComplete)});}
  });
}
