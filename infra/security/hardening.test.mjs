import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {hardenManifest} from './hardening.mjs';
const original=fs.readFileSync(new URL('../../k8s/production/petclinic.yaml',import.meta.url),'utf8');
test('runtime hardening is idempotent and retains existing database, capacity and mounts',()=>{
 const changed=hardenManifest(original);assert.equal(hardenManifest(changed),changed);
 for(const line of original.split('\n').filter(x=>/POSTGRES|secretKeyRef|claimName|memory:|maxSurge:|maxUnavailable:|platform-snapshot|replicas:/.test(x)))assert.ok(changed.includes(line));
 assert.equal((changed.match(/mountPath: \/tmp/g)||[]).length,1);
 assert.ok(changed.includes('readOnlyRootFilesystem: true'));
});
test('unknown deployment layout fails closed before promotion',()=>{
 assert.throws(()=>hardenManifest('kind: Deployment\n'));
});
