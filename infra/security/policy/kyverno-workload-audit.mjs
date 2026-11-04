// Frozen verbatim from existing admission-gate workload inventory; not admission logic.
export function frozenWorkloadAudit(items){
 return items.map(o=>{
  const spec=o.spec.template.spec,findings=[];
  for(const k of ['hostNetwork','hostPID','hostIPC'])if(spec[k])findings.push(k);
  if(spec.volumes?.some(v=>v.hostPath))findings.push('hostPath');
  for(const c of [...(spec.containers??[]),...(spec.initContainers??[])]){
   const sc=c.securityContext??{},effectiveRoot=sc.runAsNonRoot??spec.securityContext?.runAsNonRoot;
   const add=x=>findings.push(c.name+':'+x);
   if(sc.privileged)add('privileged');
   if(effectiveRoot!==true)add('missing-runAsNonRoot');
   if((sc.runAsUser??spec.securityContext?.runAsUser)===0)add('uid-zero');
   if(sc.allowPrivilegeEscalation!==false)add('escalation-not-disabled');
   if(sc.readOnlyRootFilesystem!==true)add('writable-root');
   if(sc.capabilities?.add?.length)add('added-capabilities:'+sc.capabilities.add.join(','));
   if(!sc.capabilities?.drop?.includes('ALL'))add('missing-drop-ALL');
   if(!/@sha256:[a-f0-9]{64}$/.test(c.image))add('unpinned-image');
   if(/:latest(?:@|$)/.test(c.image)||!c.image.includes(':')&&!c.image.includes('@'))add('latest-or-implicit-latest');
   for(const kind of ['requests','limits'])for(const resource of ['cpu','memory'])if(!c.resources?.[kind]?.[resource])add('missing-'+kind+'-'+resource);
  }
  return {namespace:o.metadata.namespace,kind:o.kind,name:o.metadata.name,mode:'WARN',findings};
 });
}
