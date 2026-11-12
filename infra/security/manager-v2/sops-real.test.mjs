import test from 'node:test';
import assert from 'node:assert/strict';
import {buildSopsFact, buildSopsRuntimeFacts, buildSopsEvidenceRefs, validateSopsPacket, sopsDecisionAt, sopsProjects, sopsUiCase} from './sops-real.mjs';
import {realSopsRegistry, registry} from './registry.mjs';
import {evaluate} from '../policy/engine.mjs';
const project = sopsProjects()['sops-lab'];
const RUN = 'web-123e4567-e89b-12d3-a456-426614174000';
const b64 = s => Buffer.from(s).toString('base64');
function desired(ns, name) {
  return JSON.stringify({apiVersion: 'v1', kind: 'Secret', metadata: {name, namespace: ns}, type: 'Opaque', data: {'fixture-value': b64('sops-v2-synthetic-' + name + '-v1')}});
}
function target(ns, name, over = {}) {
  const doc = JSON.parse(desired(ns, name));
  return {expected: {namespace: ns, name}, decrypt: {exitStatus: 0, stdout: desired(ns, name)},
    readSucceeded: true, actual: {data: doc.data, type: 'Opaque', metadata: {uid: 'fixture-uid-' + name}},
    applySucceeded: true, afterReadSucceeded: true,
    after: {data: doc.data, type: 'Opaque', metadata: {uid: 'fixture-uid-' + name}}, ...over};
}
const RBAC_OK = {knownRegistryGet: 'yes', registryForeignGet: 'no', registryList: 'no', registryCreate: 'no', knownGet: 'yes', foreignGet: 'no', createSecret: 'no', listSecrets: 'no', otherNamespace: 'no'};
const VRBAC_OK = {ownCredentialGet: 'yes', oldCrossGet: 'no', businessDatabaseGet: 'no', businessSecretList: 'no'};
function rawOk(over = {}) {
  return {prerequisites: {manifest: true, lease: true, tools: true, credentialPresent: true},
    sourceReadSucceeded: true, expectedTargetCount: 4, readOnly: false,
    targets: project.targets.map(([ns, name]) => target(ns, name)),
    rbac: {...RBAC_OK}, verifierRbac: {...VRBAC_OK}, reportWriteSucceeded: true, ...over};
}
function packet(over = {}) {
  return {kind: 'RestrictedLinuxSops', projectId: 'sops-lab', runId: RUN, caseId: 'compliant',
    uid: 1006, gid: 1006, groups: [1006], noNewPrivs: true,
    toolVersion: '3.13.3', toolSha256: project.toolSha256, ageVersion: '1.3.2', ageSha256: project.ageSha256,
    exitCode: 0, cleanup: 'VERIFIED', storeModel: 'FILE_FIXTURE_STORE', rbacModel: 'FIXTURE_STORE_ACL',
    startedAt: '2026-11-13T00:00:00.000Z', completedAt: '2026-11-13T00:00:05.000Z',
    stages: [{stage: 'SOURCE_READY'}, {stage: 'GATE_STARTED', pid: 42}, {stage: 'RUN_COMPLETED'}],
    cipherFacts: project.targets.map(([ns, name]) => ({namespace: ns, name, encSha256: 'a'.repeat(64), encBytes: 900, hasMac: true, recipientCount: 1})),
    raw: rawOk(), ...over};
}
test('compliant fact evaluates to frozen PASS through the sops adapter', () => {
  const f = buildSopsFact(packet());
  assert.equal(f.component, 'sops');
  assert.equal(evaluate(f, {policyVersion: 'baseline-v1', securityLevel: 'standard', mode: 'enforce'}).decision, 'PASS');
  assert.equal(sopsDecisionAt(f), 'PASS');
});
test('decrypt failure (tamper/wrong-key shape) evaluates to frozen FAIL', () => {
  const raw = rawOk();
  raw.targets[0] = target('petclinic', 'petclinic-db', {decrypt: {exitStatus: 1, stdout: ''}, applySucceeded: false});
  const f = buildSopsFact(packet({caseId: 'tampered-ciphertext', raw}));
  assert.equal(sopsDecisionAt(f), 'FAIL');
});
test('live data drift evaluates to frozen FAIL (validation failure)', () => {
  const raw = rawOk();
  const drifted = {...raw.targets[2], actual: {data: {'fixture-value': b64('sops-v2-synthetic-DRIFTED')}, type: 'Opaque', metadata: {uid: 'fixture-uid-petclinic-harbor-pull'}}, applySucceeded: false};
  drifted.after = drifted.actual;
  raw.targets[2] = drifted;
  assert.equal(sopsDecisionAt(buildSopsFact(packet({caseId: 'data-drift', raw}))), 'FAIL');
});
test('extra fixture permission evaluates to frozen FAIL', () => {
  const raw = rawOk({rbac: {...RBAC_OK, foreignGet: 'yes'}});
  assert.equal(sopsDecisionAt(buildSopsFact(packet({raw}))), 'FAIL');
});
test('missing observations stay NOT_CONFIGURED with null decision, never PASS', () => {
  const d = evaluate({component: 'sops', status: 'success', raw: {}}, {policyVersion: 'baseline-v1', securityLevel: 'standard', mode: 'enforce'});
  assert.equal(d.decision, null);
  assert.equal(d.status, 'NOT_CONFIGURED');
});
test('runtimeFacts carry the Loki fresh-run contract fields and drop raw observations', () => {
  const rt = buildSopsRuntimeFacts(packet(), RUN);
  assert.equal(rt.validationRunId, RUN);
  assert.equal(rt.classification, 'REAL_CONTROLLED_EXECUTION');
  assert.equal(rt.storeModel, 'FILE_FIXTURE_STORE');
  assert.equal(rt.cipherFacts.length, 4);
  assert.equal('raw' in rt, false);
  assert.match(rt.rawDigest, /^[a-f0-9]{64}$/);
  const refs = buildSopsEvidenceRefs(packet(), project, RUN);
  assert.equal(refs[0].validationRunId, RUN);
  assert.equal(refs[0].cipherTargets, 4);
});
test('packet validation rejects identity, tool, cipher and scope drift', () => {
  assert.equal(validateSopsPacket(packet(), {projectId: 'sops-lab', runId: RUN, project}).expectedTargetCount, 4);
  assert.throws(() => validateSopsPacket(packet({uid: 1000}), {projectId: 'sops-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSopsPacket(packet({toolSha256: '0'.repeat(64)}), {projectId: 'sops-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSopsPacket(packet({toolVersion: '3.9.0'}), {projectId: 'sops-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSopsPacket(packet({cleanup: 'INCOMPLETE'}), {projectId: 'sops-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  const noMac = packet(); noMac.cipherFacts = noMac.cipherFacts.map((c, i) => i === 0 ? {...c, hasMac: false} : c);
  assert.throws(() => validateSopsPacket(noMac, {projectId: 'sops-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  const badScope = packet(); badScope.raw = rawOk(); badScope.raw.targets[1].expected = {namespace: 'petclinic', name: 'other'};
  assert.throws(() => validateSopsPacket(badScope, {projectId: 'sops-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSopsPacket(packet(), {projectId: 'sops-cleanroom', runId: RUN, project: sopsProjects()['sops-cleanroom']}), /RUNNER_REPORT_ERROR/);
  const mq = packet({caseId: 'plaintext-masquerade'});
  mq.cipherFacts = mq.cipherFacts.map(c => c.name === 'rabbitmq-client' ? {...c, hasMac: false, recipientCount: 0} : c);
  assert.equal(validateSopsPacket(mq, {projectId: 'sops-lab', runId: RUN, project}).expectedTargetCount, 4);
});
test('sops project config is pinned to the devops wrapper facts', () => {
  assert.equal(project.targetId, 'sops-fixture-gate');
  assert.equal(project.uid, 1006); assert.equal(project.gid, 1006);
  assert.equal(project.cases['tampered-ciphertext'].expectedDecision.standard, 'FAIL');
  assert.equal(project.cases.compliant.expectedDecision.standard, 'PASS');
  assert.equal(sopsUiCase(project, 'clean'), 'compliant');
  assert.equal(sopsUiCase(project, 'controlled-finding'), 'tampered-ciphertext');
  assert.throws(() => sopsUiCase(project, 'bogus'), /SOPS_SCENARIO_NOT_AUTHORIZED/);
  const p2 = sopsProjects()['sops-cleanroom'];
  assert.equal(p2.targetId, 'sops-cleanroom-gate');
  assert.equal(sopsUiCase(p2, 'clean'), 'compliant');
});
test('realSopsRegistry exposes sops as a real runner and leaves defaults intact', () => {
  const sops = realSopsRegistry().get('sops');
  assert.equal(sops.runner, 'sops-real');
  assert.equal(sops.executionMode, 'REAL_VALIDATION');
  assert.equal(sops.normalizer, 'sops-native/v1');
  assert.equal(sops.policyAdapter, 'sops');
  assert.equal(sops.timeout, 120000);
  const demo = registry().get('sops');
  assert.equal(demo.runner, 'blocked');
  assert.equal(demo.executionMode, 'PREFLIGHT_ONLY');
});
