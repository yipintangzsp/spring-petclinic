import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const items=JSON.parse(fs.readFileSync('infra/security/integration-resources.json')).items;
test('private verifier uses own namespace credential without anonymous or signature bypass',()=>{
 const policy=items.find(x=>x.kind==='ClusterPolicy');const verification=policy.spec.rules[0].verifyImages[0];
 assert.deepEqual(verification.imageRegistryCredentials.secrets,['kyverno-registry-pull']);
 assert.equal(policy.spec.validationFailureAction,'Enforce');assert.equal(verification.required,true);assert.equal(verification.verifyDigest,true);assert.equal(verification.useCache,false);
});
test('obsolete cross-namespace binding grants nobody and new reconciliation permission is exact',()=>{
 assert.deepEqual(items.find(x=>x.kind==='RoleBinding'&&x.metadata.name==='platform-signature-pull').subjects,[]);
 const role=items.find(x=>x.kind==='Role'&&x.metadata.name==='platform-registry-secret-reconciler');
 assert.equal(role.metadata.namespace,'devsecops-system');assert.equal(role.rules.length,1);assert.deepEqual(role.rules[0].resourceNames,['kyverno-registry-pull']);assert.deepEqual(new Set(role.rules[0].verbs),new Set(['get','patch','update']));
});
