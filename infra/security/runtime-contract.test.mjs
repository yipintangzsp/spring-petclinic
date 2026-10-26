import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
const read=p=>fs.readFileSync('infra/security/'+p,'utf8');
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const rules=read('runtime/platform-rules.yaml'),lock=JSON.parse(read('runtime/lock.json')),manifest=JSON.parse(read('runtime/falco.json'));
const ds=manifest.items.find(x=>x.kind==='DaemonSet');const cm=manifest.items.find(x=>x.kind==='ConfigMap'&&x.data?.['platform-rules.yaml']);
test('runtime deployed rules, version label, manifest and locked source stay consistent',()=>{
 assert.equal(hash(read('runtime/falco.json')),lock.manifestSha256);assert.equal(hash(rules),lock.rulesetSha256);
 assert.equal(cm.data['platform-rules.yaml'].trimEnd(),rules.trimEnd());assert.equal(ds.spec.template.metadata.labels['petclinic.devops.local/runtime-ruleset'],lock.rulesetSha256.slice(0,12));
 assert.equal(ds.spec.template.spec.containers[0].resources.requests.memory,'256Mi');assert.equal(ds.spec.template.spec.containers[0].resources.limits.memory,'512Mi');
});
test('bootstrap exception requires fixed host runtime executable and scoped workload; all eight rules remain',()=>{
 assert.equal((rules.match(/^- rule: /gm)||[]).length,8);
 assert.match(rules,/proc\.exepath="\/var\/lib\/rancher\/k3s\/data\/[a-f0-9]{64}\/bin\/runc"/);assert.doesNotMatch(rules,/proc\.exepath contains runc/);
 assert.match(rules,/container\.name=petclinic/);assert.match(rules,/container\.name in \(worker, tests\)/);assert.match(rules,/proc\.cmdline in/);
});
test('grouped instant vectors show all rows; internal health reports are separate and historical logs remain',()=>{
 const d=JSON.parse(Object.values(JSON.parse(read('dashboard.json')).data)[0]);
 for(const id of [21,22,23,24,25,26,27]){const p=d.panels.find(p=>p.id===id);assert.ok(p.targets[0].expr.includes('runtime_ruleset="'+lock.rulesetLabel+'"'));assert.ok(p.targets[0].expr.includes('source="syscall"'));}
 for(const id of [23,24,25,26])assert.equal(d.panels.find(p=>p.id===id).options.reduceOptions.values,true);
 const health=d.panels.find(p=>p.id===29);assert.ok(health.targets[0].expr.includes('Falco internal: syscall event drop'));assert.ok(!health.targets[0].expr.includes('runtime_ruleset='));
 assert.ok(read('runtime/falco-logs.alloy').includes('__meta_kubernetes_pod_label_petclinic_devops_local_runtime_ruleset'));
});
