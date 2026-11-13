import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {inspectRemotePlan,validateBootstrap} from './terraform-remote.mjs';
const fixture=()=>({resource_changes:[
 {address:'kubernetes_config_map_v1.environment',change:{actions:['create'],after:{metadata:[{name:'environment-manifest',namespace:'tf-remote-lab',labels:{'petclinic.devops.local/owner':'terraform-remote-lab'}}],data:{config_revision:'v1',managed_by:'terraform',scenario:'petclinic-devops-study'}}}},
 {address:'terraform_data.coordination_probe[0]',change:{actions:['create'],after:{input:'bounded-state-lock-probe'}}}
]});
test('permits only isolated ConfigMap and fresh virtual lock probe',()=>assert.equal(inspectRemotePlan(fixture()).length,2));
test('cleanup permits only virtual probe deletion and preserves real ConfigMap',()=>{const p=fixture();p.resource_changes[0].change.actions=['no-op'];p.resource_changes[1].change.actions=['delete'];assert.equal(inspectRemotePlan(p,true).length,1);p.resource_changes[0].change.actions=['delete'];assert.throws(()=>inspectRemotePlan(p,true));});
test('rejects replacing or deleting real infrastructure',()=>{for(const actions of [['delete'],['delete','create']]){const p=fixture();p.resource_changes[0].change.actions=actions;assert.throws(()=>inspectRemotePlan(p));}});
test('rejects foreign resource, missing ConfigMap and duplicate state address',()=>{for(const address of ['kubernetes_namespace_v1.business','terraform_data.coordination_probe[0]']){const p=fixture();p.resource_changes[0].address=address;assert.throws(()=>inspectRemotePlan(p));}const p=fixture();p.resource_changes.shift();assert.throws(()=>inspectRemotePlan(p));});
test('rejects foreign namespace, ownership and additional payload',()=>{for(const mutate of [p=>p.resource_changes[0].change.after.metadata[0].namespace='petclinic',p=>p.resource_changes[0].change.after.metadata[0].labels={},p=>p.resource_changes[0].change.after.data.password='forbidden']){const p=fixture();mutate(p);assert.throws(()=>inspectRemotePlan(p));}});
const bootstrap=()=>JSON.parse(fs.readFileSync('infra/devops-lab/iac/remote/bootstrap.json','utf8'));
test('bootstrap grants only namespaced metadata permissions without compute or PVC',()=>assert.doesNotThrow(()=>validateBootstrap(bootstrap())));
test('rejects cluster-wide bindings, wildcard rights and foreign subjects',()=>{for(const mutate of [p=>p.items.find(x=>x.kind==='RoleBinding').roleRef.kind='ClusterRole',p=>p.items.find(x=>x.kind==='Role').rules[0].verbs=['*'],p=>p.items.find(x=>x.kind==='RoleBinding').subjects[0].namespace='petclinic']){const p=bootstrap();mutate(p);assert.throws(()=>validateBootstrap(p));}});
test('rejects privilege expansion through quotas or added bootstrap objects',()=>{const p=bootstrap();p.items.find(x=>x.kind==='ResourceQuota').spec.hard.pods='1';assert.throws(()=>validateBootstrap(p));const q=bootstrap();q.items.push({kind:'ClusterRoleBinding'});assert.throws(()=>validateBootstrap(q));});
