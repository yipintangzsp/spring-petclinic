import test from 'node:test';
import assert from 'node:assert/strict';
import {buildKubescapeFact, buildKubescapeRuntimeFacts, buildKubescapeEvidenceRefs, validateKubescapePacket, kubescapeProjects, kubescapeUiCase, kubescapeScanSummaries} from './kubescape-real.mjs';
import {realKubescapeRegistry, registry} from './registry.mjs';
import {evaluate} from '../policy/engine.mjs';
import {kubescapeParent} from '../policy/kubescape-parent.mjs';
const project = kubescapeProjects()['kubescape-petclinic'];
const RUN = 'web-123e4567-e89b-12d3-a456-426614174000';
const nativeReport = (extra = {}) => JSON.stringify({results: [], resources: [], summaryDetails: {controls: {}, complianceScore: 100, resourcesSeverityCounters: {}}, ...extra});
const scan = (i, report) => ({output: '.devsecops/kubescape/scan-' + i + '.json', command: {status: 0, stdout: '', stderr: '', error: null}, report: {value: report ?? nativeReport()}, hash: {value: 'a'.repeat(64)}, logWriteSucceeded: true});
const rawFor = (reports) => ({
  lock: {version: '4.0.17', source: 'https://github.com/kubescape/kubescape/releases/tag/v4.0.17', url: 'https://github.com/kubescape/kubescape/releases/download/v4.0.17/kubescape_4.0.17_linux_arm64', sha256: project.toolSha256, path: project.toolPath, operator: false, artifactRoot: project.toolArtifactRoot, artifacts: {...project.toolArtifacts}},
  holder: 'smv2-kubescape-123e4567',
  observations: {
    hashes: {[project.toolPath]: {value: project.toolSha256}, ...Object.fromEntries(Object.entries(project.toolArtifacts).map(([n, h]) => [project.toolArtifactRoot + '/' + n, {value: h}]))},
    scans: [0, 1, 2, 3].map(i => scan(i, reports?.[i])),
    lockReadSucceeded: true, sourceReadSucceeded: true, outputDirSucceeded: true, tempCreateSucceeded: true, tempChmodSucceeded: true, configWriteSucceeded: true, cleanupSucceeded: true, finalReportWriteSucceeded: true,
    lease: {status: 0, stdout: JSON.stringify({spec: {holderIdentity: 'smv2-kubescape-123e4567'}}), stderr: '', error: null},
    server: {status: 0, stdout: 'https://127.0.0.1:6443', stderr: '', error: null},
    ca: {status: 0, stdout: JSON.stringify({data: {'ca.crt': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'}}), stderr: '', error: null},
    token: {status: 0, stdout: 'REDACTED_SHA256:' + 'b'.repeat(64), stderr: '', error: null},
    secretReadCheck: {status: 0, stdout: 'no', stderr: '', error: null},
    businessWriteCheck: {status: 0, stdout: 'no', stderr: '', error: null},
  },
});
const packet = (over = {}) => ({
  kind: 'RestrictedLinuxKubescape', projectId: 'kubescape-petclinic', runId: RUN, caseId: 'cluster-audit',
  uid: 1005, gid: 1005, groups: [1005], noNewPrivs: true,
  toolVersion: '4.0.17', toolSha256: project.toolSha256, exitCode: 0, cleanup: 'VERIFIED',
  gate: {status: 'success', findings: 0, failedControls: 0, highRiskFindings: 0},
  stages: [{stage: 'SCAN_STARTED', pid: 42}, {stage: 'RUN_COMPLETED'}],
  raw: rawFor(), ...over,
});
test('fact maps a successful frozen audit execution to PASS', () => {
  const f = buildKubescapeFact(packet());
  assert.equal(f.component, 'kubescape');
  const r = evaluate(f, {policyVersion: 'baseline-v1', securityLevel: 'standard'});
  assert.equal(r.decision, 'PASS');
  assert.equal(kubescapeParent(structuredClone(f.raw)).decision, 'PASS');
});
test('execution-integrity tampering maps to frozen FAIL', () => {
  const p = packet();
  p.raw.observations.hashes[project.toolPath] = {value: '0'.repeat(64)};
  const r = evaluate(buildKubescapeFact(p), {policyVersion: 'baseline-v1', securityLevel: 'standard'});
  assert.equal(r.decision, 'FAIL');
});
test('runtimeFacts carry summaries, counts and the Loki fresh-run contract fields', () => {
  const rt = buildKubescapeRuntimeFacts(packet(), RUN);
  assert.equal(rt.validationRunId, RUN);
  assert.equal(rt.classification, 'REAL_CONTROLLED_EXECUTION');
  assert.equal(rt.scans.length, 4);
  assert.deepEqual(rt.scans.map(s => s.scope + '/' + s.framework), ['cluster/nsa', 'yaml/nsa', 'cluster/cis-v1.12.0', 'yaml/cis-v1.12.0']);
  assert.equal(rt.findings, 0);
  assert.equal(rt.auditDisposition, 'NO_FINDINGS');
  const refs = buildKubescapeEvidenceRefs(packet(), project, RUN);
  assert.equal(refs[0].validationRunId, RUN);
  assert.equal(refs[0].gateStatus, 'success');
});
test('violating workload findings are surfaced per native resource and control', () => {
  const report = nativeReport({
    results: [{resourceID: 'apps/v1//Deployment/kubescape-v2-test/smv2-violating', controls: [{controlID: 'C-0057', status: {status: 'failed'}, severity: 'High'}]}],
    resources: [{resourceID: 'apps/v1//Deployment/kubescape-v2-test/smv2-violating'}],
    summaryDetails: {controls: {'C-0057': {status: 'failed', severity: 'High'}}, complianceScore: 90, resourcesSeverityCounters: {high: 1}},
  });
  const p = packet({caseId: 'violating-workload', raw: rawFor([report, undefined, report, undefined]), violating: {namespace: 'kubescape-v2-test', deployment: 'smv2-violating', created: true, deleted: true, verifiedGone: true}, gate: {status: 'success', findings: 1, failedControls: 1, highRiskFindings: 1}});
  assert.equal(validateKubescapePacket(p, {projectId: 'kubescape-petclinic', runId: RUN, project}), true);
  const sums = kubescapeScanSummaries(p);
  assert.equal(sums[0].violatingFindings.length, 1);
  assert.equal(sums[0].violatingFindings[0].controlId, 'C-0057');
  const rt = buildKubescapeRuntimeFacts(p, RUN);
  assert.equal(rt.auditDisposition, 'WARN');
  assert.ok(rt.findings >= 1);
  assert.equal(evaluate(buildKubescapeFact(p), {policyVersion: 'baseline-v1', securityLevel: 'standard'}).decision, 'PASS');
});
test('packet validation rejects identity, lock and cleanup drift', () => {
  assert.equal(validateKubescapePacket(packet(), {projectId: 'kubescape-petclinic', runId: RUN, project}), true);
  assert.throws(() => validateKubescapePacket(packet({uid: 1000}), {projectId: 'kubescape-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  const badLock = packet(); badLock.raw = rawFor(); badLock.raw.lock = {...badLock.raw.lock, path: '/tmp/kubescape'};
  assert.throws(() => validateKubescapePacket(badLock, {projectId: 'kubescape-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateKubescapePacket(packet({cleanup: 'FAILED'}), {projectId: 'kubescape-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateKubescapePacket(packet({caseId: 'violating-workload'}), {projectId: 'kubescape-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateKubescapePacket(packet(), {projectId: 'kubescape-cleanroom', runId: RUN, project: kubescapeProjects()['kubescape-cleanroom']}), /RUNNER_REPORT_ERROR/);
});
test('second project packet validates independently', () => {
  const p2 = kubescapeProjects()['kubescape-cleanroom'];
  const p = packet({projectId: 'kubescape-cleanroom', caseId: 'posture-audit'});
  assert.equal(validateKubescapePacket(p, {projectId: 'kubescape-cleanroom', runId: RUN, project: p2}), true);
  assert.equal(p2.targetId, 'cleanroom-posture-audit');
});
test('kubescape project config is pinned to the frozen tool lock', () => {
  assert.equal(project.targetId, 'petclinic-posture-audit');
  assert.equal(project.toolVersion, '4.0.17');
  assert.equal(project.cases['violating-workload'].violating, true);
  assert.equal(kubescapeUiCase(project, 'clean'), 'cluster-audit');
  assert.equal(kubescapeUiCase(project, 'controlled-finding'), 'violating-workload');
  assert.throws(() => kubescapeUiCase(project, 'bogus'), /KUBESCAPE_SCENARIO_NOT_AUTHORIZED/);
});
test('realKubescapeRegistry exposes kubescape as a real runner and leaves defaults intact', () => {
  const ks = realKubescapeRegistry().get('kubescape');
  assert.equal(ks.runner, 'kubescape-real');
  assert.equal(ks.executionMode, 'REAL_VALIDATION');
  assert.equal(ks.normalizer, 'kubescape-native/v1');
  assert.equal(ks.policyAdapter, 'kubescape');
  assert.equal(ks.timeout, 1500000);
  const demo = registry().get('kubescape');
  assert.equal(demo.runner, 'blocked');
  assert.equal(demo.executionMode, 'PREFLIGHT_ONLY');
});
