import test from 'node:test';import assert from 'node:assert/strict';
import {registry,realBuildProvenanceRegistry} from './registry.mjs';
import {buildProvenanceProjects,verifyBuildEnvelope,buildBuildProvenanceFact,buildProvenanceDecisionAt,buildProvenanceUiCase,executeRealBuildProvenance} from './build-provenance-real.mjs';
const P=buildProvenanceProjects()['petclinic-platform'];
test('default registry keeps build-provenance blocked',()=>{const p=registry().get('build-provenance');assert.equal(p.runner,'blocked');assert.equal(p.executionMode,'PREFLIGHT_ONLY');});
test('realBuildProvenanceRegistry shape',()=>{const p=realBuildProvenanceRegistry().get('build-provenance');assert.equal(p.runner,'build-provenance-real');assert.equal(p.executionMode,'REAL_VALIDATION');assert.equal(p.normalizer,'build-provenance-native/v1');assert.equal(p.policyAdapter,'build-provenance');assert.equal(p.enabled,false);});
test('historical signed build attestation verifies with full build identity',()=>{const pkt=verifyBuildEnvelope({project:P,caseId:'historical-build'});assert.equal(pkt.exitCode,0);assert.equal(pkt.statement.predicate.buildType,'petclinic-maven-buildx-v1');assert.equal(pkt.statement.predicate.source.commit,'9a78cc89f22fa98fb1ffcc43e2ae279299471793');assert.equal(pkt.statement.predicate.builder.buildNumber,2);assert.equal(pkt.sbomCrossCheck.match,true);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'PASS');});
test('wrong commit is rejected',()=>{const pkt=verifyBuildEnvelope({project:P,caseId:'wrong-commit'});assert.equal(pkt.exitCode,1);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'FAIL');});
test('wrong digest is rejected',()=>{const pkt=verifyBuildEnvelope({project:P,caseId:'wrong-digest'});assert.equal(pkt.exitCode,1);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'FAIL');});
test('tampered envelope payload is rejected',()=>{const pkt=verifyBuildEnvelope({project:P,caseId:'tampered-envelope'});assert.equal(pkt.exitCode,1);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'FAIL');});
test('executeRealBuildProvenance returns PASS execution for historical case',async()=>{const r=await executeRealBuildProvenance(realBuildProvenanceRegistry().get('build-provenance'),{targetId:P.targetId,caseId:'historical-build'},{projectId:'petclinic-platform',runId:'web-test-bp-1'});assert.equal(r.oldDecision,'PASS');assert.equal(r.runtimeFacts.validationRunId,'web-test-bp-1');assert.equal(r.runtimeFacts.buildNumber,2);assert.match(r.runtimeFacts.jarSha256,/^[a-f0-9]{64}$/);});
test('cross-project and target mismatches are rejected',async()=>{
 const plug=realBuildProvenanceRegistry().get('build-provenance');
 await assert.rejects(()=>executeRealBuildProvenance(plug,{targetId:P.targetId,caseId:'historical-build'},{projectId:'build-provenance-cleanroom',runId:'web-test-bp-2'}),/BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED/);
 await assert.rejects(()=>executeRealBuildProvenance(plug,{targetId:'wrong-target',caseId:'historical-build'},{projectId:'petclinic-platform',runId:'web-test-bp-3'}),/BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED/);
 await assert.rejects(()=>executeRealBuildProvenance(plug,{targetId:P.targetId,caseId:'historical-build'},{projectId:'unknown-project',runId:'web-test-bp-4'}),/BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED/);
});
test('buildProvenanceUiCase maps scenarios and rejects others',()=>{assert.equal(buildProvenanceUiCase(P,'verified'),'historical-build');assert.equal(buildProvenanceUiCase(P,'rejected'),'wrong-digest');assert.throws(()=>buildProvenanceUiCase(P,'anything-else'),/BUILD_PROVENANCE_SCENARIO_NOT_AUTHORIZED/);});

// T07 C6: current-candidate (B4, candidate-build #7) build-provenance cases.
// The SBOM binding anchor on file still seals the historical candidate, so the
// cross-check honestly reports match=false for B4; decisions are unaffected.
const B4B=buildProvenanceProjects()['petclinic-platform-b4'];
test('B4 signed build attestation verifies with full build identity',()=>{const pkt=verifyBuildEnvelope({project:B4B,caseId:'b4-candidate'});assert.equal(pkt.exitCode,0);assert.equal(pkt.statement.predicate.source.commit,'318d479fb458ff229d0e10ed99ae7317f7427625');assert.equal(pkt.statement.predicate.builder.buildNumber,7);assert.equal(pkt.sbomCrossCheck.match,false);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'PASS');});
test('B4 wrong commit is rejected',()=>{const pkt=verifyBuildEnvelope({project:B4B,caseId:'b4-wrong-commit'});assert.equal(pkt.exitCode,1);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'FAIL');});
test('B4 wrong digest is rejected',()=>{const pkt=verifyBuildEnvelope({project:B4B,caseId:'b4-wrong-digest'});assert.equal(pkt.exitCode,1);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'FAIL');});
test('B4 tampered envelope payload is rejected',()=>{const pkt=verifyBuildEnvelope({project:B4B,caseId:'b4-tampered-envelope'});assert.equal(pkt.exitCode,1);assert.equal(buildProvenanceDecisionAt(buildBuildProvenanceFact(pkt)),'FAIL');});
test('executeRealBuildProvenance returns PASS execution for B4 case',async()=>{const r=await executeRealBuildProvenance(realBuildProvenanceRegistry().get('build-provenance'),{targetId:B4B.targetId,caseId:'b4-candidate'},{projectId:'petclinic-platform-b4',runId:'web-test-bp-b4-1'});assert.equal(r.oldDecision,'PASS');assert.equal(r.runtimeFacts.buildNumber,7);});
