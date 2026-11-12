import test from 'node:test';import assert from 'node:assert/strict';
import {registry,realProvenanceRegistry} from './registry.mjs';
import {provenanceProjects,buildProvenanceObservations,buildProvenanceFact,provenanceDecisionAt,provenanceUiCase,executeRealProvenance} from './provenance-real.mjs';
const P=provenanceProjects()['petclinic-platform'];
test('default registry keeps provenance blocked',()=>{const p=registry().get('provenance');assert.equal(p.runner,'blocked');assert.equal(p.executionMode,'PREFLIGHT_ONLY');});
test('realProvenanceRegistry shape',()=>{const p=realProvenanceRegistry().get('provenance');assert.equal(p.runner,'provenance-real');assert.equal(p.executionMode,'REAL_VALIDATION');assert.equal(p.normalizer,'provenance-native/v1');assert.equal(p.policyAdapter,'provenance');assert.equal(p.enabled,false);});
test('historical signed attestation verifies PASS with SBOM anchor cross-check',()=>{const pkt=buildProvenanceObservations({project:P,caseId:'historical-candidate'});assert.equal(pkt.sbomCrossCheck.match,true);assert.equal(pkt.sbomCrossCheck.anchorSealDigest,'c0b526e11ab3a6b79f9c25475a7ce2e4a3291d2af233d3378e31f3c596cb8ea5');assert.equal(provenanceDecisionAt(buildProvenanceFact(pkt)),'PASS');});
test('wrong commit is rejected FAIL',()=>{const pkt=buildProvenanceObservations({project:P,caseId:'wrong-commit'});assert.equal(provenanceDecisionAt(buildProvenanceFact(pkt)),'FAIL');});
test('wrong digest is rejected FAIL',()=>{const pkt=buildProvenanceObservations({project:P,caseId:'wrong-digest'});assert.equal(provenanceDecisionAt(buildProvenanceFact(pkt)),'FAIL');});
test('tampered envelope payload is rejected FAIL',()=>{const pkt=buildProvenanceObservations({project:P,caseId:'tampered-envelope'});assert.equal(provenanceDecisionAt(buildProvenanceFact(pkt)),'FAIL');});
test('executeRealProvenance returns PASS execution for historical case',async()=>{const r=await executeRealProvenance(realProvenanceRegistry().get('provenance'),{targetId:P.targetId,caseId:'historical-candidate'},{projectId:'petclinic-platform',runId:'web-test-prov-1'});assert.equal(r.oldDecision,'PASS');assert.equal(r.runtimeFacts.validationRunId,'web-test-prov-1');assert.equal(r.runtimeFacts.sbomCrossCheck.match,true);});
test('cross-project and target mismatches are rejected',async()=>{
 const plug=realProvenanceRegistry().get('provenance');
 await assert.rejects(()=>executeRealProvenance(plug,{targetId:P.targetId,caseId:'historical-candidate'},{projectId:'provenance-cleanroom',runId:'web-test-prov-2'}),/PROVENANCE_PROJECT_NOT_AUTHORIZED/);
 await assert.rejects(()=>executeRealProvenance(plug,{targetId:'wrong-target',caseId:'historical-candidate'},{projectId:'petclinic-platform',runId:'web-test-prov-3'}),/PROVENANCE_PROJECT_NOT_AUTHORIZED/);
 await assert.rejects(()=>executeRealProvenance(plug,{targetId:P.targetId,caseId:'historical-candidate'},{projectId:'unknown-project',runId:'web-test-prov-4'}),/PROVENANCE_PROJECT_NOT_AUTHORIZED/);
});
test('provenanceUiCase maps scenarios and rejects others',()=>{assert.equal(provenanceUiCase(P,'verified'),'historical-candidate');assert.equal(provenanceUiCase(P,'rejected'),'wrong-digest');assert.throws(()=>provenanceUiCase(P,'anything-else'),/PROVENANCE_SCENARIO_NOT_AUTHORIZED/);});
