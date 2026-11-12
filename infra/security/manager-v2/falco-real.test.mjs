import test from 'node:test';
import assert from 'node:assert/strict';
import {parseFalcoEvents, falcoProjects} from './falco-real.mjs';
import {realFalcoRegistry, registry} from './registry.mjs';
import {falcoCollectorPacket} from './falco/collector.mjs';

const line = (rule, pod, extra = {}) => JSON.stringify({
  time: '2026-11-12T14:00:00.000000000Z', rule, priority: 'Warning',
  output_fields: {'k8s.ns.name': 'devsecops-test', 'k8s.pod.name': pod, 'container.name': 'test', 'container.id': 'abcdef012345', 'proc.name': 'cat', 'evt.type': 'openat', 'evt.res': 'SUCCESS', 'evt.arg.name': '/etc/shadow', 'user.uid': 0, ...extra},
});

test('parseFalcoEvents keeps only Platform Runtime events for the target pod', () => {
  const log = [
    'Thu Nov 12 14:00:00 2026: [libs]: noise line',
    line('Platform Runtime Sensitive Read', 'falco-v2-pos-1'),
    line('Platform Runtime Shell', 'falco-v2-pos-1', {'proc.name': 'sh', 'evt.type': 'execve'}),
    line('Platform Runtime Sensitive Read', 'some-other-pod'),
    line('Some Other Rule', 'falco-v2-pos-1'),
    '{broken json',
  ].join('\n');
  const events = parseFalcoEvents(log, 'falco-v2-pos-1');
  assert.equal(events.length, 2);
  assert.equal(events[0].rule, 'Platform Runtime Sensitive Read');
  assert.equal(events[0].path, '/etc/shadow');
  assert.equal(events[0].priority, 'Warning');
  assert.equal(events[1].rule, 'Platform Runtime Shell');
});

test('parseFalcoEvents returns empty for a benign window', () => {
  assert.deepEqual(parseFalcoEvents('Thu Nov 12: [libs]: noise\n', 'falco-v2-neg-1'), []);
});

test('falco project config is pinned to the live sensor facts', () => {
  const p = falcoProjects()['petclinic-runtime'];
  assert.equal(p.targetId, 'devops-falco-sensor');
  assert.equal(p.falcoVersion, '0.45.1');
  assert.equal(p.rulesetLabel, '59752c1132f0');
  assert.equal(p.testNamespace, 'devsecops-test');
});

test('realFalcoRegistry exposes falco as a real runner and leaves defaults intact', () => {
  const falco = realFalcoRegistry().get('falco');
  assert.equal(falco.runner, 'falco-real');
  assert.equal(falco.executionMode, 'REAL_VALIDATION');
  assert.equal(falco.normalizer, 'falco-native/v1');
  assert.equal(falco.policyAdapter, 'falco-final');
  assert.equal(falco.timeout, 30000);
  const demo = registry().get('falco');
  assert.equal(demo.runner, 'blocked');
  assert.equal(demo.executionMode, 'PREFLIGHT_ONLY');
});

test('falco collector config pins the dedicated restricted entry identity (G-F2)', () => {
  const p = falcoProjects()['petclinic-runtime'];
  assert.equal(p.collectorEntryUser, 'security-falco');
  assert.equal(p.collectorEntryHost, '127.0.0.1');
  assert.equal(p.collectorUid, 1007);
  assert.equal(p.collectorGid, 1007);
  assert.equal(p.collectorProjectId, 'petclinic-runtime');
  assert.equal(p.collectorServiceAccount, 'security-falco-collector');
  assert.equal(p.collectorServiceAccountNamespace, 'devsecops-system');
});

const packetFixture = (overrides = {}) => {
  const sensorPods = JSON.stringify({items: [{metadata: {name: 'platform-falco-fwwfd'}, status: {podIP: '10.42.0.185'}}]});
  const ok = stdout => ({status: 0, stdout});
  return {
    kind: 'FalcoCollectorPacket', projectId: 'petclinic-runtime', windowEndMs: 1794496655180,
    identity: {user: 'security-falco', uid: 1007, gid: 1007, serviceAccount: 'security-falco-collector', serviceAccountNamespace: 'devsecops-system', kubeconfig: '/var/lib/security-falco/kubeconfig.yaml'},
    results: {ds: ok('{}'), sensorPods: ok(sensorPods), node: ok('{}'), workloads: ok('{}'), diagnosticLog: ok(''), sampleLog: ok(''), fullLog: ok('')},
    health: {ok: true, status: 200},
    ...overrides,
  };
};

test('falcoCollectorPacket accepts a well-formed entry packet and shapes results', () => {
  const p = falcoProjects()['petclinic-runtime'];
  const out = falcoCollectorPacket(packetFixture(), p, 1794496655180);
  assert.equal(out.sensorPod.metadata.name, 'platform-falco-fwwfd');
  assert.equal(out.identity.uid, 1007);
  assert.equal(out.health.ok, true);
  assert.equal(out.fullLogText, '');
});

test('falcoCollectorPacket rejects a packet from a non-dedicated identity', () => {
  const p = falcoProjects()['petclinic-runtime'];
  const bad = packetFixture({identity: {user: 'zhang', uid: 1000, gid: 1000, serviceAccount: 'security-falco-collector', serviceAccountNamespace: 'devsecops-system'}});
  assert.throws(() => falcoCollectorPacket(bad, p, 1794496655180), /RUNNER_ERROR/);
});

test('falcoCollectorPacket rejects a packet for a different window or project', () => {
  const p = falcoProjects()['petclinic-runtime'];
  assert.throws(() => falcoCollectorPacket(packetFixture(), p, 1794496655181), /RUNNER_ERROR/);
  assert.throws(() => falcoCollectorPacket(packetFixture({projectId: 'other-project'}), p, 1794496655180), /RUNNER_ERROR/);
});
