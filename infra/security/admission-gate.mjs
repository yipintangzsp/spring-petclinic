import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {spawnSync} from 'node:child_process';
import {createAdmissionPartCollector,writeKyvernoPart,completeKyverno,kyvernoConfiguration,runKey} from './summary-v2/collectors/kyverno.mjs';
// Frozen-replay harnesses strip imports; fall back to a no-op collector so
// the module executes byte-identically there. Collection is passive.
const collector=typeof createAdmissionPartCollector==='function'?createAdmissionPartCollector()
 :{probe(){},policy(){},owner(){},workloads(){},reportWrite(){},reads(){},observations:{}};
// probe() is source-extracted by a frozen-replay harness; it reaches the
// collector only through this soft global bridge (absent there -> no-op).
globalThis.__t08aKyvernoProbe=r=>collector.probe(r);
const namespace='devsecops-execution', tool=JSON.parse(fs.readFileSync('infra/security/tools-lock.json')).gitleaks;
const pod={apiVersion:'v1',kind:'Pod',metadata:{name:'devsecops-contract-probe',namespace},spec:{automountServiceAccountToken:false,restartPolicy:'Never',securityContext:{runAsNonRoot:true,runAsUser:65532,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'probe',image:tool.image,command:['gitleaks','version'],securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},resources:{requests:{cpu:'100m',memory:'256Mi'},limits:{cpu:'1',memory:'512Mi'}}}]}};
const evidence={source:fs.readFileSync('.git-sha','utf8').trim(),startedAt:new Date().toISOString(),cases:[],status:'failed'};
function probe(spec,denied){
 const r=spawnSync('kubectl',['--request-timeout=20s','create','--dry-run=server','-f','-','-o','json'],{input:JSON.stringify(spec),encoding:'utf8',timeout:25000,maxBuffer:1024*1024});
 globalThis.__t08aKyvernoProbe?.(r);
 if(r.error)throw r.error;
 if(denied ? r.status===0||!/devsecops-workload-contract|devsecops-production-baseline/.test(r.stderr) : r.status!==0)throw Error('Admission mismatch: '+r.stderr.slice(-1500));
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
 // Probe the supplemental live policy independently of the scanner-only contract.
 const contract=JSON.parse(fs.readFileSync('infra/security/production-baseline.json'));
 const actual=spawnSync('kubectl',['--request-timeout=20s','get','clusterpolicy',contract.metadata.name,'-o','json'],{encoding:'utf8',timeout:25000});
 collector.policy(actual);
 if(actual.status!==0)throw Error('Production baseline policy unavailable');
 const liveSpec=JSON.parse(actual.stdout).spec;
 for(const desiredRule of contract.spec.rules){const liveRule=liveSpec.rules.find(x=>x.name===desiredRule.name);if(!isDeepStrictEqual(liveRule?.validate?.cel,desiredRule.validate.cel)||!isDeepStrictEqual(liveRule?.preconditions,desiredRule.preconditions)||!isDeepStrictEqual(liveRule?.match,desiredRule.match))throw Error('Live baseline expressions differ: '+desiredRule.name);}
 if(liveSpec.validationFailureAction!=='Enforce')throw Error('Production baseline must enforce');
 const scannerProbe=structuredClone(pod);scannerProbe.spec.containers[0].image=JSON.parse(fs.readFileSync('infra/security/scanner-tools.json')).baseImage;evidence.cases.push({case:'existing-semgrep-zap-runtime',mode:'PASS',...probe(scannerProbe,false)});
 const productionProbe=structuredClone(pod);productionProbe.metadata.namespace='petclinic';productionProbe.spec.containers[0].image=JSON.parse(fs.readFileSync('infra/messaging/dependencies.json')).runtime;
 evidence.cases.push({case:'production-compliant-worker-image',mode:'PASS',...probe(productionProbe,false)});
 const closing={
 added_dangerous_capability:p=>p.spec.containers[0].securityContext.capabilities.add=['SYS_ADMIN'],
 unauthorized_registry:p=>p.spec.containers[0].image='unapproved.invalid/security/probe@sha256:'+'1'.repeat(64),
 container_uid_zero:p=>p.spec.containers[0].securityContext.runAsUser=0,
 pod_uid_zero:p=>{p.spec.securityContext.runAsUser=0;},
 unrestricted_init_container:p=>p.spec.initContainers=[{...structuredClone(p.spec.containers[0]),name:'init',securityContext:{runAsNonRoot:false,runAsUser:0,allowPrivilegeEscalation:true,readOnlyRootFilesystem:false,capabilities:{add:['SYS_ADMIN']}}}],
 privileged_init_container:p=>{delete p.spec.securityContext.seccompProfile;p.spec.initContainers=[{...structuredClone(p.spec.containers[0]),name:'init',securityContext:{privileged:true,allowPrivilegeEscalation:true}}];},
 init_registry:p=>p.spec.initContainers=[{...structuredClone(p.spec.containers[0]),name:'init',image:'unapproved.invalid/security/init@sha256:'+'2'.repeat(64)}]
 };
 for(const [name,change] of Object.entries(closing)){const p=structuredClone(productionProbe);change(p);evidence.cases.push({case:name,mode:'FAIL',...probe(p,true)});}
 evidence.warningProbes=[];evidence.exceptions=[];
 const exceptions=JSON.parse(fs.readFileSync('infra/security/production-exceptions.json'));
 for(const ex of exceptions.exceptions){
  const r=spawnSync('kubectl',['--request-timeout=20s','get','pods','-n',ex.namespace,'-o','json'],{encoding:'utf8',timeout:25000,maxBuffer:8*1024*1024});
  collector.owner(r);
  if(r.status!==0)throw Error('Exception workload read failed');
  const source=JSON.parse(r.stdout).items.find(p=>p.metadata.ownerReferences?.some(o=>o.uid===ex.owner.uid));if(!source)throw Error('Approved exception owner absent: '+ex.id);
  const spec={apiVersion:'v1',kind:'Pod',metadata:{name:'baseline-exception-'+ex.id.toLowerCase(),namespace:ex.namespace,ownerReferences:source.metadata.ownerReferences},spec:source.spec};
  evidence.exceptions.push({id:ex.id,mode:'precise-exception',...probe(spec,false)});
  const wrongOwner=structuredClone(spec);wrongOwner.metadata.ownerReferences[0].uid='00000000-0000-0000-0000-000000000000';evidence.cases.push({case:ex.id+'-wrong-owner-denied',mode:'FAIL',...probe(wrongOwner,true)});
  const changedEnv=structuredClone(spec);const special=[...(changedEnv.spec.initContainers??[]),...changedEnv.spec.containers].find(c=>c.name===ex.container);special.env=[...(special.env??[]),{name:'BASELINE_UNTRUSTED_INPUT',value:'synthetic-test'}];evidence.cases.push({case:ex.id+'-modified-env-denied',mode:'FAIL',...probe(changedEnv,true)});
  if(ex.id==='sonarInit'){const script=structuredClone(spec);script.spec.volumes.find(v=>v.name==='init-sysctl').configMap.name='untrusted-script-fixture';evidence.cases.push({case:'sonarInit-script-source-denied',mode:'FAIL',...probe(script,true)});}
  const extra=structuredClone(spec);
  if(ex.id==='falco')extra.spec.containers[0].securityContext.capabilities.add.push('SYS_ADMIN');
  else if(ex.id==='nodeExporter')extra.spec.hostIPC=true;
  else extra.spec.containers[0].securityContext={privileged:true,allowPrivilegeEscalation:true};
  evidence.cases.push({case:ex.id+'-extra-permission-denied',mode:'FAIL',...probe(extra,true)});
 }
 // Observe current templates without applying scanner restrictions to production/system namespaces.
 const live=spawnSync('kubectl',['--request-timeout=20s','get','deploy,ds,sts','-A','-o','json'],{encoding:'utf8',timeout:25000,maxBuffer:16*1024*1024});
 collector.workloads(live);
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
 evidence.scope={enforcedNamespaces:exceptions.scopeNamespaces,productionExpansion:true,registryAllowlist:'Reviewed namespace-specific repository prefixes enforced',exceptions:exceptions.exceptions,remainingWarn:'Missing nonroot/readonly/resources, legacy tags outside scanner namespace; other namespaces remain inventory WARN'};
 evidence.status='success';
}finally{fs.mkdirSync('.devsecops',{recursive:true});
 let writeError;try{fs.writeFileSync('.devsecops/admission-gate.json',JSON.stringify(evidence,null,2));collector.reportWrite(true);}catch(e){collector.reportWrite(false);writeError=e;}
 if(typeof completeKyverno==='function'){const cfg=kyvernoConfiguration();collector.reads(cfg.configurationReadSucceeded,true);
 writeKyvernoPart('.','admission',runKey(),collector.observations,cfg.configuration,evidence.status==='success'?'success':'failed');
 completeKyverno();}
 if(writeError)throw writeError;}
console.log('Kyverno server dry-run: '+evidence.cases.length+' enforced cases passed; '+evidence.warningProbes.length+' gaps audited WARN; no workloads created');
