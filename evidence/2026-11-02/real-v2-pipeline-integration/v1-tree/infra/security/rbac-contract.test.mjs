import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const items=JSON.parse(fs.readFileSync(new URL('./controller.json',import.meta.url))).items;
test('Argo tracking instance label still selects Kyverno official core RBAC',()=>{
 const roles=items.filter(x=>x.kind==='ClusterRole').map(x=>({...x,metadata:{...x.metadata,labels:{...x.metadata.labels,'app.kubernetes.io/instance':'platform-devsecops'}}}));
 const aggregate=roles.find(x=>x.metadata.name==='kyverno:admission-controller');
 const selected=roles.filter(role=>aggregate.aggregationRule.clusterRoleSelectors.some(s=>Object.entries(s.matchLabels).every(([key,value])=>role.metadata.labels[key]===value)));
 assert(selected.some(r=>r.metadata.name==='kyverno:admission-controller:core'));
 assert(selected.flatMap(r=>r.rules??[]).some(r=>r.apiGroups.includes('apiextensions.k8s.io')&&r.resources.includes('customresourcedefinitions')&&r.verbs.includes('get')));
});
test('Argo tracking labels preserve controller ServiceMonitor selection',()=>{
 for(const monitor of items.filter(x=>x.kind==='ServiceMonitor'))assert(items.some(s=>s.kind==='Service'&&Object.entries(monitor.spec.selector.matchLabels).every(([k,v])=>({...s.metadata.labels,'app.kubernetes.io/instance':'platform-devsecops'})[k]===v)));
});
