import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createSourceOwner} from './owner.mjs';
import {gateView,validateResult} from './results.mjs';
import {EXPECTED_SOURCES} from './inventory.mjs';
import {digest} from './codec.mjs';
import {consumeArtifact,encodeArtifact,finalizeArtifact,legacyModuleStatus,writeImmutableArtifact} from './artifact.mjs';
import {summaryV2} from './producer.mjs';
import {preApprovalPolicyInput} from './promotion-input.mjs';
import {binding,fixture,inputFor} from './fixture-harness.mjs';

test('1 source has exactly one actual Engine evaluation; Gate reuses digest',async()=>{
  const owner=createSourceOwner(binding),facts=inputFor('WARN'),before=JSON.stringify(facts);
  const r=await owner.evaluateOnce('trivy',facts);
  assert.equal(r.result.decision,'WARN');assert.equal(owner.get('trivy'),r);
  assert.equal(gateView(r,binding).resultDigest,r.resultDigest);assert.deepEqual(owner.counts(),{trivy:1});
  assert.equal(JSON.stringify(facts),before);assert.ok(Object.isFrozen(r.result.effectivePolicy));
});
test('duplicate concurrent and completed evaluations are rejected before second Engine call',async()=>{
  const owner=createSourceOwner(binding),first=owner.evaluateOnce('trivy',inputFor('PASS'));
  await assert.rejects(owner.evaluateOnce('trivy',inputFor('PASS')),/duplicate source evaluation/);await first;
  await assert.rejects(owner.evaluateOnce('trivy',inputFor('FAIL')),/duplicate source evaluation/);assert.equal(owner.counts().trivy,1);
});
test('Summary and candidate Promotion precondition reuse the exact artifact; zero further evaluations',async()=>{
  const f=await fixture(),before=f.owner.counts(),summary=summaryV2(f.packet,f.context),p=preApprovalPolicyInput(f.packet,f.context);
  assert.equal(summary.resolvedSources.length,16);assert.deepEqual(f.owner.counts(),before);
  for(const id of EXPECTED_SOURCES){assert.equal(before[id],1);assert.equal(summary.resolvedSources.find(x=>x.sourceId===id).resultDigest,f.owner.get(id).resultDigest);}
  assert.equal(p.artifactDigest,f.packet.digest);
});
test('missing expected source is rejected',async()=>{const f=await fixture();assert.throws(()=>finalizeArtifact({...f.artifact,sources:f.sources.slice(1)}),/missing expected source/);});
test('duplicate source is rejected',async()=>{const f=await fixture();assert.throws(()=>finalizeArtifact({...f.artifact,sources:[f.sources[0],...f.sources.slice(0,-1)]}),/duplicate/);});
test('wrong/alias/post-scope source identities rejected',async()=>{
  for(const id of ['semgrep','security-approval-promotion','unknown'])await assert.rejects(createSourceOwner(binding).evaluateOnce(id,{component:id,status:'skipped'}),/wrong canonical/);
});
test('stale build/source/project/run identity rejected',async()=>{const f=await fixture();for(const [key,value] of Object.entries({build:2,source:'d'.repeat(40),project:'other',runId:'other',job:'other'}))assert.throws(()=>consumeArtifact(f.packet,{...f.context,binding:{...binding,[key]:value}}),/stale/);});
test('malformed source results rejected, even if untrusted result digest is recalculated',async()=>{
  const f=await fixture();for(const change of [r=>delete r.rawFactDigest,r=>r.result.securityLevel='typo',r=>r.result.decision='PASS',r=>r.result.effectivePolicy.trivy.High='typo']){
    const r=structuredClone(f.sources[0]);change(r);delete r.resultDigest;r.resultDigest=digest(r);assert.throws(()=>validateResult(r,binding),/POLICY_ERROR/);
  }
});
test('POLICY_ERROR preserved without inventing default standard',async()=>{
  const f=await fixture('PASS',{profile:'typo'}),s=summaryV2(f.packet,f.context);
  assert.equal(s.policy.state,'POLICY_ERROR');assert.equal(s.policy.securityLevel,undefined);assert.equal(s.resolvedSources[0].status,'POLICY_ERROR');
  assert.equal(f.artifact.completeness,'COMPLETE');assert.equal(f.artifact.aggregate.result,'FAILURE');assert.throws(()=>preApprovalPolicyInput(f.packet,f.context),/not eligible/);
});
for(const state of ['SKIPPED','NOT_CONFIGURED'])test(state+' is preserved rather than PASS',async()=>{
  const f=await fixture(state),s=summaryV2(f.packet,f.context),r=s.resolvedSources.find(r=>r.sourceId==='trivy');assert.equal(r.status,state);assert.equal(r.decision,null);
});
test('candidate mismatch rejected',async()=>{const f=await fixture();assert.throws(()=>summaryV2(f.packet,{...f.context,binding:{...binding,candidate:'registry.invalid/fixture@sha256:'+'b'.repeat(64)}}),/stale/);});
test('artifact bytes require trusted owner digest, not self-reported hash',async()=>{
  const f=await fixture(),value=JSON.parse(f.packet.bytes);value.legacySummary.build_result='FORGED';
  const packet=encodeArtifact(value);assert.throws(()=>consumeArtifact(packet,f.context),/integrity/);
  assert.throws(()=>consumeArtifact({bytes:'{malformed'},{...f.context,digest:digest({})}),/integrity/);
});
test('COMPLETE requires finalized aggregate and original external Gate observations',async()=>{
  const f=await fixture();for(const change of [a=>a.finalized=false,a=>delete a.externalChecks.snapshotBefore,a=>a.result='FAILURE']){
    const aggregate=structuredClone(f.aggregate);change(aggregate);assert.throws(()=>finalizeArtifact({...f.artifact,aggregate}),/POLICY_ERROR/);
  }
});
test('missing parent execution observations cannot become COMPLETE',async()=>{
  const f=await fixture(),owner=createSourceOwner(binding),r=await owner.evaluateOnce('sops',{component:'sops',status:'success',raw:{status:'success',secrets:[]}});
  assert.equal(r.result.status,'NOT_CONFIGURED');assert.equal(r.evidenceComplete,false);
  assert.throws(()=>finalizeArtifact({...f.artifact,sources:f.sources.map(x=>x.sourceId==='sops'?r:x)}),/incomplete raw/);
});
test('explicit immutable file refuses replacement and cleans isolated output',async()=>{
  const f=await fixture(),dir=fs.mkdtempSync(path.join(os.tmpdir(),'policy-artifact-'));
  try{const first=writeImmutableArtifact(dir,f.artifact);assert.equal(fs.readFileSync(first.path,'utf8'),f.packet.bytes);assert.equal(fs.statSync(first.path).mode&0o777,0o400);assert.throws(()=>writeImmutableArtifact(dir,f.artifact),/EEXIST/);}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('pre-approval excludes future approval/promotion facts recursively',async()=>{
  const f=await fixture();for(const key of ['promotionApproved','approvedDigest','promotionResult','runtimeAfter','releaseSuccess']){
    assert.throws(()=>finalizeArtifact({...f.artifact,legacySummary:{...f.artifact.legacySummary,nested:{[key]:'forged'}}}),/future promotion/);
  }
  const s=summaryV2(f.packet,f.context);assert.equal(s.promotionApproved,undefined);assert.equal(s.promotionResult,undefined);
});
test('anti-self-approval: forged future result rejected even under a newly encoded artifact',async()=>{
  const f=await fixture(),forged=structuredClone(f.artifact);forged.legacySummary.promotionApproved=true;
  const packet=encodeArtifact(forged);assert.throws(()=>preApprovalPolicyInput(packet,{...f.context,digest:packet.digest}),/future promotion/);
  const result={phase:'post-promotion',PromotionResult:{status:'SUCCESS'}};
  assert.throws(()=>preApprovalPolicyInput(encodeArtifact(result),{...f.context,digest:encodeArtifact(result).digest}),/incomplete artifact/);
});
test('default, explicit low and strict metadata come from the real Engine',async()=>{
  for(const [config,level,decision] of [[{},'standard','WARN'],[{securityLevel:'low'},'low','WARN'],[{securityLevel:'strict'},'strict','FAIL']]){
    const f=await fixture('WARN',config),s=summaryV2(f.packet,f.context);assert.equal(s.policy.securityLevel,level);assert.equal(s.resolvedSources.find(x=>x.sourceId==='trivy').decision,decision);assert.deepEqual(s.policy.effectivePolicy,f.sources[0].result.effectivePolicy);
  }
});
test('component/project overrides keep target identity and raw facts unchanged',async()=>{
  const base=await fixture('WARN'),component=await fixture('WARN',{componentOverrides:{trivy:{Medium:'FAIL'}}}),project=await fixture('WARN',{project:'fixture',componentOverrides:{trivy:{Medium:'FAIL'}},projectOverride:{project:'fixture',components:{trivy:{Medium:'WARN'}}}});
  assert.equal(component.sources.find(x=>x.sourceId==='trivy').result.decision,'FAIL');assert.equal(project.sources.find(x=>x.sourceId==='trivy').result.decision,'WARN');
  for(const f of [base,component,project])assert.equal(f.sources.find(x=>x.sourceId==='trivy').rawFactDigest,base.sources.find(x=>x.sourceId==='trivy').rawFactDigest);
  const s=summaryV2(project.packet,project.context);assert.deepEqual(s.policy.appliedOverrides.map(x=>x.layer),['component','project']);assert.equal(s.policy.effectivePolicy.zap.Medium,'WARN');
});
test('invalid level/policy/profile/override never falls back to low/standard',async()=>{
  for(const config of [{securityLevel:'typo'},{policyVersion:'typo'},{profile:'typo'},{componentOverrides:{unknown:{High:'PASS'}}},{project:'fixture',projectOverride:{project:'other',components:{}}}]){
    const r=await createSourceOwner(binding).evaluateOnce('trivy',inputFor('PASS'),config);assert.equal(r.result,null);assert.equal(r.error.code,'POLICY_ERROR');
  }
});
test('legacy wrapper audit exit10 remains WARN; enforce nonzero remains FAIL',()=>{
  assert.equal(legacyModuleStatus(0,'enforce'),'success');assert.equal(legacyModuleStatus(10,'audit'),'warn');for(const code of [1,10,20,127,137])assert.equal(legacyModuleStatus(code,'enforce'),'failed');
});
test('original Jenkins external failure and inherited status are not severity-reduced',async()=>{
  const f=await fixture();for(const field of ['snapshotBefore','readOnlyReleaseVerification']){
    const aggregate=structuredClone(f.aggregate);aggregate.externalChecks[field]='failed';aggregate.result='FAILURE';assert.equal(finalizeArtifact({...f.artifact,aggregate}).aggregate.result,'FAILURE');
  }
  const aggregate={...f.aggregate,inheritedBuildResult:'UNSTABLE',result:'UNSTABLE'};assert.equal(finalizeArtifact({...f.artifact,aggregate}).aggregate.result,'UNSTABLE');
});
