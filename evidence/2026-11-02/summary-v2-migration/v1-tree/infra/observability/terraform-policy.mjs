const owner='terraform-remote-lab',lab='tf-remote-lab',store='terraform-state';
const address='kubernetes_config_map_v1.environment',probe='terraform_data.coordination_probe[0]';
const addresses=['kubernetes_namespace_v1.lab','kubernetes_resource_quota_v1.budget','kubernetes_config_map_v1.environment'];
export function inspectPlan(plan) {
 const changes=plan.resource_changes??[];
 if(changes.length!==3||changes.some(c=>!addresses.includes(c.address)||JSON.stringify(c.change.actions)!=='["create"]')||new Set(changes.map(c=>c.address)).size!==3)
  throw Error('Only exactly three isolated creates are allowed; preserve any existing state/resources');
 const after=Object.fromEntries(changes.map(c=>[c.address,c.change.after]));
 const ns=after[addresses[0]],quota=after[addresses[1]],cm=after[addresses[2]];
 if(ns.metadata?.[0]?.name!=='tf-devops-lab'||ns.metadata[0].labels?.['petclinic.devops.local/owner']!=='terraform-iac-lab')throw Error('Unexpected namespace ownership');
 if(quota.metadata?.[0]?.name!=='lab-budget'||quota.metadata[0].namespace!=='tf-devops-lab'||cm.metadata?.[0]?.name!=='environment-manifest'||cm.metadata[0].namespace!=='tf-devops-lab')throw Error('Unexpected resource scope');
 const hard=quota.spec?.[0]?.hard;
 for(const k of ['pods','persistentvolumeclaims','secrets','services','requests.storage'])if(hard?.[k]!=='0')throw Error('Pod/storage/secret/service quota must remain zero');
 if(hard.configmaps!=='4'||cm.data?.managed_by!=='terraform'||cm.data.scenario!=='petclinic-devops-study'||cm.data.config_revision!=='v1')throw Error('Unexpected lab settings');
 return changes.map(c=>({address:c.address,actions:c.change.actions}));
}
export function inspectRemotePlan(plan,cleanup=false){
 const changes=[];
 if(plan.resource_changes?.length!==2||new Set(plan.resource_changes.map(c=>c.address)).size!==2)throw Error('Exactly the demo ConfigMap and bounded probe must be present');
 for(const c of plan.resource_changes??[]){
  if(![address,probe].includes(c.address))throw Error('Foreign remote state resource; preserved');
  const actions=c.change.actions,after=c.change.after;
  if(c.address===address){
   if(!['["no-op"]','["create"]','["update"]'].includes(JSON.stringify(actions)))throw Error('ConfigMap removal/replacement is forbidden');
   if(after?.metadata?.[0]?.name!=='environment-manifest'||after.metadata[0].namespace!==lab||after.metadata[0].labels?.['petclinic.devops.local/owner']!==owner||JSON.stringify(Object.keys(after.data??{}).sort())!==JSON.stringify(['config_revision','managed_by','scenario'])||after.data.config_revision!=='v1'||after.data.managed_by!=='terraform'||after.data.scenario!=='petclinic-devops-study')throw Error('Unexpected ConfigMap scope/data');
  }else if(JSON.stringify(actions)!==(cleanup?'["delete"]':'["create"]'))throw Error('Only the bounded state-only coordination probe may be created/removed');
  if(JSON.stringify(actions)!=='["no-op"]')changes.push({address:c.address,actions});
 }
 if(cleanup&&(changes.length!==1||changes[0].address!==probe))throw Error('Cleanup may remove only the state-only probe');
 if(!cleanup&&!changes.some(c=>c.address===probe))throw Error('A new bounded probe is required to test the real apply lock');
 return changes;
}
export function validateBootstrap(doc){
 const expected=new Set(['Namespace/terraform-state','Namespace/tf-remote-lab','ResourceQuota/terraform-state/terraform-budget','ResourceQuota/tf-remote-lab/terraform-budget','ServiceAccount/tf-remote-lab/terraform-runner','Role/terraform-state/terraform-runtime','Role/tf-remote-lab/terraform-runtime','RoleBinding/terraform-state/terraform-runtime','RoleBinding/tf-remote-lab/terraform-runtime']);
 if(doc.items?.length!==expected.size)throw Error('Unexpected bootstrap resource count');
 for(const x of doc.items){
  const m=x.metadata,key=[x.kind,m.namespace,m.name].filter(Boolean).join('/');
  if(!expected.delete(key)||m.labels?.['petclinic.devops.local/owner']!==owner)throw Error('Unexpected bootstrap scope/owner');
  if(x.kind==='Role'){
   const wants=m.namespace===store?[['','secrets'],['coordination.k8s.io','leases']]:[['','configmaps']];
   if(x.rules.length!==wants.length||x.rules.some((r,i)=>JSON.stringify(r.apiGroups)!==JSON.stringify([wants[i][0]])||JSON.stringify(r.resources)!==JSON.stringify([wants[i][1]])||JSON.stringify(r.verbs)!=='["get","list","create","update","patch","delete"]'))throw Error('Unexpected runtime permissions');
  }
  if(x.kind==='RoleBinding'&&(JSON.stringify(x.subjects)!==JSON.stringify([{kind:'ServiceAccount',name:'terraform-runner',namespace:lab}])||x.roleRef.kind!=='Role'||x.roleRef.name!=='terraform-runtime'||x.roleRef.apiGroup!=='rbac.authorization.k8s.io'))throw Error('Unexpected binding');
  if(x.kind==='ServiceAccount'&&x.automountServiceAccountToken!==false)throw Error('No automatic long-lived credential mounts');
  if(x.kind==='ResourceQuota'){
   const h=x.spec.hard;
   for(const k of ['pods','persistentvolumeclaims','services','requests.storage'])if(h[k]!=='0')throw Error('No compute/storage growth permitted');
   if(h.secrets!==(m.namespace===store?'4':'0')||h['count/leases.coordination.k8s.io']!==(m.namespace===store?'4':'0')||h.configmaps!=='4')throw Error('Unexpected metadata quota');
  }
 }
}
