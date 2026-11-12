import test from 'node:test';
import assert from 'node:assert/strict';
import {buildSonarFact, buildSonarRaw, buildSonarRuntimeFacts, buildSonarEvidenceRefs, validateSonarPacket, sonarProjects, sonarUiCase} from './sonar-real.mjs';
import {realSonarRegistry, registry} from './registry.mjs';
import {evaluate} from '../policy/engine.mjs';
import {sonarDecision} from '../policy/sonar-evidence.mjs';
const project = sonarProjects()['sonarqube-petclinic'];
const RUN = 'web-123e4567-e89b-12d3-a456-426614174000';
const packet = (over = {}) => ({
  kind: 'RestrictedLinuxSonar', projectId: 'sonarqube-petclinic', runId: RUN, caseId: 'clean-scan',
  uid: 1003, gid: 982, groups: [982], noNewPrivs: true, componentKey: 'smv2-clean', mode: 'scan',
  serverVersion: '26.3.0.120487', toolVersion: '7.2.0.5079', toolSha256: project.toolSha256,
  task: {id: '4439ebdf-1d78-4ebc-8a86-af02b2fcb794', type: 'REPORT', componentKey: 'smv2-clean', analysisId: 'e55d5df4-6ae6-48dc-9ff9-cd188c863a53', status: 'SUCCESS', executedAt: '2026-11-12T16:27:02+0000'},
  gate: {status: 'OK', conditions: [{metricKey: 'new_violations', status: 'OK', comparator: 'GT', errorThreshold: '0', actualValue: '0'}], ignoredConditions: false, caycStatus: 'compliant'},
  measures: {alert_status: 'OK', new_violations: '0'}, issuesTotal: 1,
  scans: [{projectVersion: RUN, ceTaskId: '4439ebdf-1d78-4ebc-8a86-af02b2fcb794', analysisId: 'e55d5df4-6ae6-48dc-9ff9-cd188c863a53', exitCode: 0}],
  exitCode: 0, startedAt: '2026-11-12T00:00:00.000Z', completedAt: '2026-11-12T00:00:01.000Z',
  stages: [{stage: 'SCANNER_STARTED', pid: 42}, {stage: 'CE_TASK_BOUND'}, {stage: 'RUN_COMPLETED'}], cleanup: 'VERIFIED', ...over,
});
test('fact maps server OK gate to frozen PASS', () => {
  const f = buildSonarFact(packet());
  assert.equal(f.component, 'sonarqube');
  assert.equal(f.raw.binding.projectKey, 'smv2-clean');
  const r = evaluate(f, {policyVersion: 'baseline-v1', securityLevel: 'standard'});
  assert.equal(r.decision, 'PASS');
  assert.equal(r.sonarEvidence.authoritativeStatus, 'OK');
});
test('fact maps server ERROR gate to frozen FAIL', () => {
  const gate = {status: 'ERROR', conditions: [{metricKey: 'new_violations', status: 'ERROR', comparator: 'GT', errorThreshold: '0', actualValue: '8'}], ignoredConditions: true, caycStatus: 'compliant'};
  const base = packet();
  const f = buildSonarFact(packet({caseId: 'violating-scan', componentKey: 'smv2-gatelab-123e4567', gate, task: {...base.task, componentKey: 'smv2-gatelab-123e4567'}}));
  assert.equal(evaluate(f, {policyVersion: 'baseline-v1', securityLevel: 'standard'}).decision, 'FAIL');
  assert.equal(sonarDecision(f.raw).decision, 'FAIL');
});
test('binding tampering is rejected by the frozen adapter', () => {
  const raw = buildSonarRaw(packet());
  raw.binding.taskId = 'other';
  assert.throws(() => sonarDecision(raw), /POLICY_ERROR/);
  const raw2 = buildSonarRaw(packet());
  raw2.task.task.status = 'FAILED';
  assert.throws(() => sonarDecision(raw2), /POLICY_ERROR/);
});
test('runtimeFacts carry the Loki fresh-run contract fields', () => {
  const rt = buildSonarRuntimeFacts(packet(), RUN);
  assert.equal(rt.validationRunId, RUN);
  assert.equal(rt.classification, 'REAL_CONTROLLED_EXECUTION');
  assert.equal(rt.gateStatus, 'OK');
  assert.equal(rt.analysisId, 'e55d5df4-6ae6-48dc-9ff9-cd188c863a53');
  const refs = buildSonarEvidenceRefs(packet(), project, RUN);
  assert.equal(refs[0].validationRunId, RUN);
  assert.equal(refs[0].gateStatus, 'OK');
});
test('packet validation rejects identity, component and binding drift', () => {
  assert.equal(validateSonarPacket(packet(), {projectId: 'sonarqube-petclinic', runId: RUN, project}), true);
  assert.throws(() => validateSonarPacket(packet({uid: 1000}), {projectId: 'sonarqube-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSonarPacket(packet({componentKey: 'petclinic'}), {projectId: 'sonarqube-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSonarPacket(packet({gate: {status: 'OK', conditions: [{metricKey: 'new_violations', status: 'OK', comparator: 'GT', errorThreshold: '0'}]}}), {projectId: 'sonarqube-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSonarPacket(packet({scans: [{projectVersion: RUN, ceTaskId: 'other', analysisId: 'e55d5df4-6ae6-48dc-9ff9-cd188c863a53', exitCode: 0}]}), {projectId: 'sonarqube-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateSonarPacket(packet(), {projectId: 'sonarqube-cleanroom', runId: RUN, project: sonarProjects()['sonarqube-cleanroom']}), /RUNNER_REPORT_ERROR/);
});
test('second project packet validates independently', () => {
  const p2 = sonarProjects()['sonarqube-cleanroom'];
  const p = packet({projectId: 'sonarqube-cleanroom', caseId: 'cleanroom-scan'});
  assert.equal(validateSonarPacket(p, {projectId: 'sonarqube-cleanroom', runId: RUN, project: p2}), true);
  assert.equal(p2.targetId, 'cleanroom-quality-gate');
});
test('violating packet validates against the run-derived fresh component key', () => {
  const base = packet();
  const p = packet({caseId: 'violating-scan', componentKey: 'smv2-gatelab-123e4567', task: {...base.task, componentKey: 'smv2-gatelab-123e4567'}, scans: [{projectVersion: RUN + '-base', ceTaskId: 'aaaaaaaa-0000-0000-0000-000000000000', analysisId: 'bbbbbbbb-0000-0000-0000-000000000000', exitCode: 0}, {projectVersion: RUN + '-test', ceTaskId: base.task.id, analysisId: base.task.analysisId, exitCode: 0}]});
  assert.equal(validateSonarPacket(p, {projectId: 'sonarqube-petclinic', runId: RUN, project}), true);
  assert.throws(() => validateSonarPacket(packet({caseId: 'violating-scan', componentKey: 'smv2-gatelab-ffffff', task: {...base.task, componentKey: 'smv2-gatelab-ffffff'}}), {projectId: 'sonarqube-petclinic', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
});
test('sonar project config is pinned to the live server facts', () => {
  assert.equal(project.targetId, 'petclinic-quality-gate');
  assert.equal(project.serverVersion, '26.3.0.120487');
  assert.equal(project.cases['violating-scan'].expectedGate, 'ERROR');
  assert.equal(sonarUiCase(project, 'clean'), 'clean-scan');
  assert.equal(sonarUiCase(project, 'controlled-finding'), 'violating-scan');
  assert.throws(() => sonarUiCase(project, 'bogus'), /SONAR_SCENARIO_NOT_AUTHORIZED/);
});
test('realSonarRegistry exposes sonarqube as a real runner and leaves defaults intact', () => {
  const sonar = realSonarRegistry().get('sonarqube');
  assert.equal(sonar.runner, 'sonar-real');
  assert.equal(sonar.executionMode, 'REAL_VALIDATION');
  assert.equal(sonar.normalizer, 'sonar-native/v1');
  assert.equal(sonar.policyAdapter, 'sonarqube');
  assert.equal(sonar.timeout, 180000);
  const demo = registry().get('sonarqube');
  assert.equal(demo.runner, 'blocked');
  assert.equal(demo.executionMode, 'PREFLIGHT_ONLY');
});
