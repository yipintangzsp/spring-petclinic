import {test} from 'node:test';
import assert from 'node:assert/strict';
import {inspectPlan} from './terraform-ci.mjs';
const fixture=()=>({resource_changes:[
 {address:'kubernetes_namespace_v1.lab',change:{actions:['create'],after:{metadata:[{name:'tf-devops-lab',labels:{'petclinic.devops.local/owner':'terraform-iac-lab'}}]}}},
 {address:'kubernetes_resource_quota_v1.budget',change:{actions:['create'],after:{metadata:[{name:'lab-budget',namespace:'tf-devops-lab'}],spec:[{hard:{pods:'0',persistentvolumeclaims:'0',secrets:'0',services:'0','requests.storage':'0',configmaps:'4'}}]}}},
 {address:'kubernetes_config_map_v1.environment',change:{actions:['create'],after:{metadata:[{name:'environment-manifest',namespace:'tf-devops-lab'}],data:{managed_by:'terraform',scenario:'petclinic-devops-study',config_revision:'v1'}}}}
]});
test('allows only three new isolated lab resources',()=>assert.equal(inspectPlan(fixture()).length,3));
test('rejects deletion, replacement and updates to existing resources',()=>{for(const actions of [['delete'],['delete','create'],['update'],['no-op']]){const p=fixture();p.resource_changes[0].change.actions=actions;assert.throws(()=>inspectPlan(p));}});
test('rejects outside resources and duplicate addresses',()=>{for(const address of ['kubernetes_namespace_v1.business','kubernetes_config_map_v1.environment']){const p=fixture();p.resource_changes[0].address=address;assert.throws(()=>inspectPlan(p));}});
test('rejects business namespaces and changed owner',()=>{const p=fixture();p.resource_changes[0].change.after.metadata[0].name='petclinic';assert.throws(()=>inspectPlan(p));const q=fixture();q.resource_changes[0].change.after.metadata[0].labels={};assert.throws(()=>inspectPlan(q));});
test('rejects quotas permitting Pods, persistent storage, secrets or services',()=>{for(const key of ['pods','persistentvolumeclaims','secrets','services','requests.storage']){const p=fixture();p.resource_changes[1].change.after.spec[0].hard[key]='1';assert.throws(()=>inspectPlan(p));}});
test('rejects config in a foreign namespace or changed business input',()=>{const p=fixture();p.resource_changes[2].change.after.metadata[0].namespace='petclinic';assert.throws(()=>inspectPlan(p));const q=fixture();q.resource_changes[2].change.after.data.config_revision='out-of-band';assert.throws(()=>inspectPlan(q));});
