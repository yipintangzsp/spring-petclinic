import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {assessPreflight, preflight, productionNodes, requireHarborRegistry, requireFreshScannerMetadata} from './release-preflight.mjs';
function snapshot(now = Date.now()) {
 return {hostSample: {at: now / 1000,mac: {diskFreeMiB: 30 * 1024,freePercent: 40,efiAllocatedMiB: 1.1}},storage: Object.fromEntries(productionNodes.map(name => [name, {fs: {time: new Date(now).toISOString(),capacityBytes: 250 * 1024 ** 3,availableBytes: 70 * 1024 ** 3},runtime: {imageFs: {time: new Date(now).toISOString(),capacityBytes: 250 * 1024 ** 3,availableBytes: 70 * 1024 ** 3}}}])), nodes: productionNodes.map(name => ({metadata: {name}, spec: {}, status: {conditions:
  ['Ready', 'MemoryPressure', 'DiskPressure', 'PIDPressure'].map(type => ({type, status: type === 'Ready' ? 'True' : 'False'}))}})),
  leases: productionNodes.map(name => ({metadata: {name}, spec: {renewTime: new Date(now).toISOString()}})),
  pods: productionNodes.map((name, i) => ({metadata: {name: `pod-${i}`, uid: `uid-${i}`}, spec: {nodeName: name}, status: {conditions: [{type: 'Ready', status: 'True'}]}})),
  slices: [{endpoints: productionNodes.map((nodeName, i) => ({nodeName, targetRef: {uid: `uid-${i}`}, conditions: {ready: true, serving: true, terminating: false}}))}],
  deployment: {spec: {replicas: 3}, status: {availableReplicas: 3}}};
}
test('three healthy nodes with live endpoints pass', () => assert.equal(assessPreflight(snapshot()).ok, true));
test('all Pods Ready on devops cannot conceal disconnected workers', () => {
 const s = snapshot(); s.pods.forEach(p => p.spec.nodeName = 'devops');
 s.slices[0].endpoints.forEach(e => e.nodeName = 'devops');
 s.nodes[1].status.conditions[0].status = 'Unknown';
 assert.match(assessPreflight(s).blockers.join(';'), /aliyun-worker: NODE_NOT_READY/);
});
test('stale, absent and future Leases fail even with cached Ready', () => {
 for (const time of [undefined, new Date(Date.now() - 60000).toISOString(), new Date(Date.now() + 60000).toISOString()]) {
  const s = snapshot(); s.leases[2].spec.renewTime = time;
  assert.match(assessPreflight(s).blockers.join(';'), /ucloud-worker: LEASE_NOT_FRESH/);
 }
});
test('terminating or mismatched endpoint UID is not counted as available business capacity', () => {
 const s = snapshot(); s.slices[0].endpoints[0].conditions.terminating = true;
 s.slices[0].endpoints[1].targetRef.uid = 'deleted-old-pod';
 const result = assessPreflight(s); assert.equal(result.readyEndpointPods, 1); assert.equal(result.ok, false);
});
test('maintenance and pressure block publishing', () => {
 const s = snapshot(); s.nodes[1].spec.unschedulable = true; s.nodes[2].status.conditions[1].status = 'True';
 assert.equal(assessPreflight(s).ok, false);
});
test('a retained unreachable taint blocks release but the existing cloud taint does not', () => {
 const s = snapshot(); s.nodes[2].spec.taints = [{key: 'cloud', value: 'true', effect: 'NoSchedule'}];
 assert.equal(assessPreflight(s).ok, true);
 s.nodes[2].spec.taints.push({key: 'node.kubernetes.io/unreachable', effect: 'NoExecute'});
 assert.match(assessPreflight(s).blockers.join(';'), /UNHEALTHY_NODE_TAINT/);
});
test('healthy snapshots with advancing Leases pass the observation window', async () => {
 const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'petclinic-preflight-'));
 try {
  const result = await preflight({collect: () => snapshot(), windowMs: 20, pollMs: 5, output: path.join(dir, 'pass.json')});
  assert.equal(result.ok, true);
 } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
test('a frozen fresh Lease must advance across the observation window', async () => {
 const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'petclinic-preflight-'));
 const s = snapshot(), output = path.join(dir, 'failure.json');
 try {
  await assert.rejects(preflight({collect: () => s, windowMs: 10, pollMs: 5, output}), /LEASE_NOT_PROGRESSING/);
  assert.match(JSON.parse(fs.readFileSync(output)).failure, /LEASE_NOT_PROGRESSING/);
 } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
test('API failures fail closed and still retain evidence', async () => {
 const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'petclinic-preflight-'));
 const output = path.join(dir, 'failure.json');
 try {
  await assert.rejects(preflight({collect: () => {throw Error('API unavailable');}, output}), /API unavailable/);
  assert.equal(JSON.parse(fs.readFileSync(output)).failure, 'API unavailable');
 } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test('explicit local targets exclude an unhealthy cloud worker and report it', () => {
 const s = snapshot(); s.targetNodes = ['devops'];
 s.pods.forEach(p => p.spec.nodeName = 'devops');
 s.slices[0].endpoints.forEach(e => e.nodeName = 'devops');
 s.nodes[2].status.conditions[0].status = 'Unknown';
 s.leases[2].spec.renewTime = new Date(Date.now() - 600000).toISOString();
 const result = assessPreflight(s);
 assert.equal(result.ok, true);
 assert.equal(result.excludedNodes.some(n => n.name === 'ucloud-worker'), true);
});
test('a selector matching no target nodes blocks publishing', () => {
 const s = snapshot(); s.targetNodes = [];
 assert.equal(assessPreflight(s).ok, false);
});

test('disk pressure False cannot conceal insufficient future build headroom', () => {
 for (const freeGiB of [14, 37]) {
  const s = snapshot();s.storage.devops.fs.availableBytes = freeGiB * 1024 ** 3;
  assert.match(assessPreflight(s).blockers.join(';'), /devops: nodefs DISK_HEADROOM/);
 }
});
test('missing or stale image filesystem samples fail closed', () => {
 const s = snapshot(); delete s.storage.devops.runtime.imageFs;
 assert.match(assessPreflight(s).blockers.join(';'), /imagefs FRESH_DISK_MEASUREMENT_REQUIRED/);
 s.storage.devops.runtime.imageFs = {...s.storage.devops.fs,time:new Date(Date.now()-91000).toISOString()};
 assert.match(assessPreflight(s).blockers.join(';'), /imagefs FRESH_DISK_MEASUREMENT_REQUIRED/);
});

test('saved EFI memory state blocks new builds even before host disk fills', () => {
 const s = snapshot();s.hostSample.mac.efiAllocatedMiB = 26 * 1024;
 assert.match(assessPreflight(s).blockers.join(';'), /EFI_ALLOCATION_REQUIRES_MAINTENANCE/);
});
test('missing and stale host evidence and low host disk block release', () => {
 const s = snapshot();s.hostSample.at -= 91;s.hostSample.mac.diskFreeMiB = 12000;
 assert.match(assessPreflight(s).blockers.join(';'), /FRESH_HOST_MEASUREMENT_REQUIRED/);
 assert.match(assessPreflight(s).blockers.join(';'), /MAC_DISK_BELOW_16_GIB/);
 delete s.hostSample;
 assert.equal(assessPreflight(s).ok,false);
});

test('Harbor requires both ready registry and controller ports before expensive build work', () => {
 const slices = [{ports: [{name: 'http-registry'}, {name: 'http-controller'}],
  endpoints: [{conditions: {ready: true, terminating: false}}]}];
 assert.doesNotThrow(() => requireHarborRegistry(slices));
 assert.throws(() => requireHarborRegistry([]), /HARBOR_REGISTRY_UNAVAILABLE/);
 slices[0].endpoints[0].conditions.ready = false;
 assert.throws(() => requireHarborRegistry(slices), /HARBOR_REGISTRY_UNAVAILABLE/);
 slices[0].endpoints[0].conditions = {ready: true, terminating: true};
 assert.throws(() => requireHarborRegistry(slices), /HARBOR_REGISTRY_UNAVAILABLE/);
 slices[0].endpoints[0].conditions.terminating = false;
 slices[0].ports.pop();
 assert.throws(() => requireHarborRegistry(slices), /http-controller/);
});

test('Both scanner databases must be fresh before costly build work', () => {
 const now = Date.now();
 const metadata = version => ({Version: version, UpdatedAt: new Date(now - 10000).toISOString(),
  DownloadedAt: new Date(now - 5000).toISOString(), NextUpdate: new Date(now + 60000).toISOString()});
 const good = {'db': metadata(2), 'java-db': metadata(1)};
 assert.doesNotThrow(() => requireFreshScannerMetadata(good, now));
 for (const kind of ['db', 'java-db']) {
  const stale = structuredClone(good); stale[kind].NextUpdate = new Date(now).toISOString();
  assert.throws(() => requireFreshScannerMetadata(stale, now), /REFRESH_REQUIRED/);
  delete stale[kind]; assert.throws(() => requireFreshScannerMetadata(stale, now), /REFRESH_REQUIRED/);
  stale[kind] = {...good[kind], Version: 99};
  assert.throws(() => requireFreshScannerMetadata(stale, now), /REFRESH_REQUIRED/);
 }
});
