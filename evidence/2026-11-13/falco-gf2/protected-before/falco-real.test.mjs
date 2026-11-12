import test from 'node:test';
import assert from 'node:assert/strict';
import {parseFalcoEvents, falcoProjects} from './falco-real.mjs';
import {realFalcoRegistry, registry} from './registry.mjs';

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
