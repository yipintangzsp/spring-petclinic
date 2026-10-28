import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const namespace='devsecops-execution', tool=JSON.parse(fs.readFileSync('infra/security/tools-lock.json')).gitleaks;
const pod={apiVersion:'v1',kind:'Pod',metadata:{name:'devsecops-contract-probe',namespace},spec:{automountServiceAccountToken:false,restartPolicy:'Never',securityContext:{runAsNonRoot:true,runAsUser:65532,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'probe',image:tool.image,command:['gitleaks','version'],securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},resources:{requests:{cpu:'100m',memory:'256Mi'},limits:{cpu:'1',memory:'512Mi'}}}]}};
const evidence={source:fs.readFileSync('.git-sha','utf8').trim(),startedAt:new Date().toISOString(),cases:[],status:'failed'};
function probe(spec,denied){
 const r=spawnSync('kubectl',['--request-timeout=20s','create','--dry-run=server','-f','-','-o','json'],{input:JSON.stringify(spec),encoding:'utf8',timeout:25000,maxBuffer:1024*1024});
 if(r.error)throw r.error;
 if(denied ? r.status===0||!/devsecops-workload-contract/.test(r.stderr) : r.status!==0)throw Error('Admission mismatch: '+r.stderr.slice(-1500));
 return {allowed:r.status===0,diagnostic:denied?r.stderr.slice(-1800):'server dry-run accepted; no Pod created'};
}
try{
 evidence.cases.push({case:'compliant-pod',...probe(pod,false)});
 const mutations={
 mutable_image:p=>p.spec.containers[0].image='alpine:latest',
 host_network:p=>p.spec.hostNetwork=true,host_pid:p=>p.spec.hostPID=true,host_ipc:p=>p.spec.hostIPC=true,
 host_path:p=>p.spec.volumes=[{name:'escape',hostPath:{path:'/etc'}}],
 privileged:p=>{p.spec.containers[0].securityContext.privileged=true;p.spec.containers[0].securityContext.allowPrivilegeEscalation=true;delete p.spec.securityContext.seccompProfile;},
 escalation:p=>p.spec.containers[0].securityContext.allowPrivilegeEscalation=true,
 writable_root:p=>p.spec.containers[0].securityContext.readOnlyRootFilesystem=false,
 missing_drop_all:p=>delete p.spec.containers[0].securityContext.capabilities,
 missing_limits:p=>delete p.spec.containers[0].resources.limits,
 missing_memory_limit:p=>delete p.spec.containers[0].resources.limits.memory,
 token_mount:p=>p.spec.automountServiceAccountToken=true,
 root_identity:p=>p.spec.securityContext.runAsNonRoot=false,
 missing_nonroot:p=>delete p.spec.securityContext.runAsNonRoot,
 missing_seccomp:p=>delete p.spec.securityContext.seccompProfile
 };
 for(const [name,change] of Object.entries(mutations)){const p=structuredClone(pod);change(p);evidence.cases.push({case:name,mode:'FAIL',...probe(p,true)});}
 // Deliberately unproven gaps stay WARN; do not claim the existing policy blocks them.
 const defaulted=structuredClone(pod);defaulted.spec.containers[0].resources.limits={cpu:'100m',memory:'256Mi'};delete defaulted.spec.containers[0].resources.requests;
 evidence.cases.push({case:'requests-defaulted-from-explicit-limits',mode:'PASS',...probe(defaulted,false)});
 evidence.warningProbes=[];
 const gaps={
 added_dangerous_capability:p=>p.spec.containers[0].securityContext.capabilities.add=['SYS_ADMIN'],
 unauthorized_registry:p=>p.spec.containers[0].image='unapproved.invalid/security/probe@sha256:'+'1'.repeat(64),
 container_uid_zero:p=>p.spec.containers[0].securityContext.runAsUser=0,
 unrestricted_init_container:p=>p.spec.initContainers=[{...structuredClone(p.spec.containers[0]),name:'init',securityContext:{runAsNonRoot:false,runAsUser:0,allowPrivilegeEscalation:true,readOnlyRootFilesystem:false,capabilities:{add:['SYS_ADMIN']}}}]
 };
 for(const [name,change] of Object.entries(gaps)){
  const p=structuredClone(pod);change(p);
  const r=spawnSync('kubectl',['--request-timeout=20s','create','--dry-run=server','-f','-','-o','json'],{input:JSON.stringify(p),encoding:'utf8',timeout:25000,maxBuffer:1024*1024});
  if(r.error||r.status!==0&&!/devsecops-workload-contract/.test(r.stderr))throw Error('WARN probe unavailable: '+name+': '+r.stderr.slice(-1000));
  evidence.warningProbes.push({case:name,mode:'WARN',allowed:r.status===0,diagnostic:r.status===0?'Existing contract does not reject this case; no workload created':r.stderr.slice(-1800)});
 }
 // Observe current templates without applying scanner restrictions to production/system namespaces.
 const live=spawnSync('kubectl',['--request-timeout=20s','get','deploy,ds,sts','-A','-o','json'],{encoding:'utf8',timeout:25000,maxBuffer:16*1024*1024});
 if(live.error||live.status!==0)throw Error('Workload inventory unavailable');
 evidence.workloadAudit=JSON.parse(live.stdout).items.map(o=>{
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
 evidence.scope={enforcedNamespaces:['devsecops-execution'],productionExpansion:false,registryAllowlist:'WARN: not yet reviewed',exceptions:'No broad namespace or policy exceptions added. Special workload needs recorded as audit observations; production admission scope unchanged.'};
 evidence.status='success';
}finally{fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/admission-gate.json',JSON.stringify(evidence,null,2));}
console.log('Kyverno server dry-run: '+evidence.cases.length+' enforced cases passed; '+evidence.warningProbes.length+' gaps audited WARN; no workloads created');
