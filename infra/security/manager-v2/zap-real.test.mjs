import test from 'node:test';
import assert from 'node:assert/strict';
import {buildZapFact, buildZapRaw, buildZapRuntimeFacts, buildZapEvidenceRefs, validateZapPacket, summarizeZapReport, zapDecisionAt, zapProjects, zapUiCase} from './zap-real.mjs';
import {realZapRegistry, registry} from './registry.mjs';
import {evaluate} from '../policy/engine.mjs';
import {classifyZap} from '../zap-policy.mjs';
import {sha} from '../summary-v2/codec.mjs';
const project = zapProjects()['zap-lab'];
const RUN = 'web-123e4567-e89b-12d3-a456-426614174000';
const cleanReport = {'@version': '2.17.0', '@generated': 'Thu, 13 Nov 2026 00:00:00 GMT', site: [{'@name': 'http://127.0.0.1:18113', '@host': '127.0.0.1', '@port': '18113', '@ssl': 'false', alerts: []}]};
const piiReport = {'@version': '2.17.0', '@generated': 'Thu, 13 Nov 2026 00:00:00 GMT', site: [{'@name': 'http://127.0.0.1:18114', '@host': '127.0.0.1', '@port': '18114', '@ssl': 'false', alerts: [
  {pluginid: '10062', name: 'PII Disclosure', riskcode: '3', riskdesc: 'High', count: '1', instances: [{uri: 'http://127.0.0.1:18114/', method: 'GET'}]},
  {pluginid: '10038', name: 'Content Security Policy (CSP) Header Not Set', riskcode: '2', riskdesc: 'Medium', count: '1', instances: [{uri: 'http://127.0.0.1:18114/', method: 'GET'}]},
  {pluginid: '10021', name: 'X-Content-Type-Options Header Missing', riskcode: '1', riskdesc: 'Low', count: '1', instances: [{uri: 'http://127.0.0.1:18114/', method: 'GET'}]},
]}]};
const packet = (report, kase, over = {}) => {
  const reportText = JSON.stringify(report);
  const sum = summarizeZapReport(report);
  return {
    kind: 'RestrictedLinuxZap', projectId: 'zap-lab', runId: RUN, caseId: 'clean',
    uid: 1004, gid: 981, groups: [981], noNewPrivs: true,
    target: kase.target, targetImage: kase.targetImage,
    toolVersion: '2.17.0', toolSha256: project.toolSha256,
    exitCode: 0, reportText, reportSha256: sha(reportText),
    alertsTotal: sum.alerts.length, alerts: sum.alerts, riskCounts: sum.riskCounts,
    startedAt: '2026-11-13T00:00:00.000Z', completedAt: '2026-11-13T00:00:30.000Z',
    stages: [{stage: 'FIXTURE_STARTED', pid: 41}, {stage: 'SCAN_STARTED', pid: 42}, {stage: 'RUN_COMPLETED'}], cleanup: 'VERIFIED', ...over,
  };
};
const cleanPacket = (over = {}) => packet(cleanReport, project.cases.clean, over);
const piiPacket = (over = {}) => packet(piiReport, project.cases['pii-disclosure'], {caseId: 'pii-disclosure', ...over});
test('clean fact evaluates to frozen PASS at standard level', () => {
  const f = buildZapFact(cleanPacket());
  assert.equal(f.component, 'zap');
  assert.equal(f.raw.context.targetImage, 'loopback-fixture/zap-v2-clean');
  assert.equal(f.raw.approved.schema, 1);
  assert.deepEqual(f.raw.approved.confirmations, []);
  assert.equal(evaluate(f, {policyVersion: 'baseline-v1', securityLevel: 'standard', mode: 'enforce'}).decision, 'PASS');
  assert.equal(zapDecisionAt(f, 'standard'), 'PASS');
  const c = classifyZap(f.raw.report, f.raw.context, f.raw.approved);
  assert.equal(c.rawHigh, 0); assert.equal(c.blocking.length, 0); assert.equal(c.warnings.length, 0);
});
test('pii fact: native High stays WARN at standard and FAILs at strict (frozen level table)', () => {
  const f = buildZapFact(piiPacket());
  const c = classifyZap(f.raw.report, f.raw.context, f.raw.approved);
  assert.equal(c.rawHigh, 1); assert.equal(c.unconfirmedHigh, 1); assert.equal(c.blocking.length, 0);
  assert.equal(c.warnings.find(w => w.pluginid === '10062').gateReason, 'High lacks reviewed exact-target exploit confirmation or is ordinary information');
  assert.equal(zapDecisionAt(f, 'standard'), 'WARN');
  assert.equal(zapDecisionAt(f, 'strict'), 'FAIL');
  assert.equal(evaluate(f, {policyVersion: 'baseline-v1', securityLevel: 'strict', mode: 'enforce'}).decision, 'FAIL');
});
test('runtimeFacts carry the Loki fresh-run contract fields and drop report bytes', () => {
  const rt = buildZapRuntimeFacts(piiPacket(), RUN);
  assert.equal(rt.validationRunId, RUN);
  assert.equal(rt.classification, 'REAL_CONTROLLED_EXECUTION');
  assert.equal(rt.reportSha256, piiPacket().reportSha256);
  assert.equal(rt.alertsTotal, 3);
  assert.equal(rt.riskCounts['3'], 1);
  assert.equal('reportText' in rt, false);
  const refs = buildZapEvidenceRefs(piiPacket(), project, RUN);
  assert.equal(refs[0].validationRunId, RUN);
  assert.equal(refs[0].targetImage, 'loopback-fixture/zap-v2-pii');
});
test('packet validation rejects identity, target, tool and report drift', () => {
  assert.deepEqual(validateZapPacket(cleanPacket(), {projectId: 'zap-lab', runId: RUN, project}), cleanReport);
  assert.throws(() => validateZapPacket(cleanPacket({uid: 1000}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket({target: 'http://127.0.0.1:9999/'}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket({toolSha256: '0'.repeat(64)}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket({toolVersion: '2.16.0'}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket({reportText: cleanPacket().reportText + ' '}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(piiPacket({alertsTotal: 99}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket({cleanup: 'INCOMPLETE'}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket({stages: [{stage: 'RUN_COMPLETED'}]}), {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
  assert.throws(() => validateZapPacket(cleanPacket(), {projectId: 'zap-cleanroom', runId: RUN, project: zapProjects()['zap-cleanroom']}), /RUNNER_REPORT_ERROR/);
});
test('external target inside the native report is rejected', () => {
  const evil = JSON.parse(JSON.stringify(cleanReport));
  evil.site[0]['@host'] = 'example.com'; evil.site[0]['@name'] = 'http://example.com:18113';
  const p = packet(evil, project.cases.clean);
  assert.throws(() => validateZapPacket(p, {projectId: 'zap-lab', runId: RUN, project}), /RUNNER_REPORT_ERROR/);
});
test('zap project config is pinned to the devops wrapper facts', () => {
  assert.equal(project.targetId, 'zap-loopback-fixture');
  assert.equal(project.uid, 1004); assert.equal(project.gid, 981);
  assert.equal(project.cases['pii-disclosure'].expectedDecision.strict, 'FAIL');
  assert.equal(project.cases['pii-disclosure'].expectedDecision.standard, 'WARN');
  assert.equal(zapUiCase(project, 'clean'), 'clean');
  assert.equal(zapUiCase(project, 'controlled-finding'), 'pii-disclosure');
  assert.throws(() => zapUiCase(project, 'bogus'), /ZAP_SCENARIO_NOT_AUTHORIZED/);
  const p2 = zapProjects()['zap-cleanroom'];
  assert.equal(p2.targetId, 'zap-cleanroom-fixture');
  assert.equal(zapUiCase(p2, 'clean'), 'cleanroom-clean');
});
test('realZapRegistry exposes zap as a real runner and leaves defaults intact', () => {
  const zap = realZapRegistry().get('zap');
  assert.equal(zap.runner, 'zap-real');
  assert.equal(zap.executionMode, 'REAL_VALIDATION');
  assert.equal(zap.normalizer, 'zap-native/v1');
  assert.equal(zap.policyAdapter, 'zap');
  assert.equal(zap.timeout, 240000);
  const demo = registry().get('zap');
  assert.equal(demo.runner, 'blocked');
  assert.equal(demo.executionMode, 'PREFLIGHT_ONLY');
});
