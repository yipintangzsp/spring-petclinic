import fs from 'node:fs';
import crypto from 'node:crypto';
import {frozenWorkloadAudit} from './kyverno-workload-audit.mjs';
import {isDeepStrictEqual} from 'node:util';
// Validate existing observed command outcomes and exact source/live alignment only.
// No CEL/admission/RBAC privilege algorithm is implemented here.
export function kyvernoParent(raw){
 const contract=JSON.parse(fs.readFileSync(new URL('./versions/kyverno-parent-baseline-v1.json',import.meta.url)));
 for(const [name,sha]of Object.entries(contract.sourceHashes)){const local=new URL('../'+name.replace('infra/security/',''),import.meta.url);if(crypto.createHash('sha256').update(fs.readFileSync(local)).digest('hex')!==sha)throw Error('POLICY_ERROR: frozen Kyverno source changed; baseline revalidation required');}

 if(!raw?.configuration||!raw?.observations)return {status:'NOT_CONFIGURED',decision:null,reason:'Complete parent observations required'};
 const c=raw.configuration,o=raw.observations,checks=[],warnings=[];let probeIndex=0;
 const requireValue=(id,ok)=>{checks.push({id,passed:!!ok});if(!ok)throw Error(id);};
 const command=(r,id,checkError=false)=>{requireValue(id+'-command',!!r&&r.status===0&&(!checkError||!r.error));return r.stdout;};
 const parse=(r,id)=>JSON.parse(command(r,id));
 const probe=(denied,id)=>{
  const r=o.probes[probeIndex++];requireValue(id+'-executed',!!r&&!r.error);
  requireValue(id,denied?r.status!==0&&/devsecops-workload-contract|devsecops-production-baseline/.test(r.stderr):r.status===0);
 };
 try{
  requireValue('configuration-read',o.configurationReadSucceeded===true);requireValue('source-read',o.sourceReadSucceeded===true);
  // These property accesses also exist in the original request construction.
  requireValue('tool-config',!!c.tools.gitleaks);
  const d=parse(o.rbac[0],'controller');requireValue('controller-available',d.status.availableReplicas===1);
  for(let i=1;i<=2;i++)requireValue('crd-get-'+i,command(o.rbac[i],'crd-'+i).trim()==='yes');
  const role=parse(o.rbac[3],'role');requireValue('aggregated-role',role.rules.some(r=>r.apiGroups.includes('apiextensions.k8s.io')&&r.resources.includes('customresourcedefinitions')&&r.verbs.includes('get')));
  const app=parse(o.rbac[4],'gitops');requireValue('gitops',app.status.sync.status==='Synced'&&app.status.health.status==='Healthy');
  requireValue('rbac-report-write',o.rbacReportWriteSucceeded===true);
  probe(false,'compliant-pod');for(let i=0;i<contract.scannerNegativeCases;i++)probe(true,'scanner-negative-'+i);
  const live=parse(o.policy,'policy').spec;
  for(const expected of c.baseline.spec.rules){const actual=live.rules.find(r=>r.name===expected.name);for(const key of ['cel'])requireValue('policy-'+expected.name+'-'+key,isDeepStrictEqual(actual?.validate?.[key],expected.validate[key]));for(const key of ['preconditions','match'])requireValue('policy-'+expected.name+'-'+key,isDeepStrictEqual(actual?.[key],expected[key]));}
  requireValue('policy-enforce',live.validationFailureAction==='Enforce');
  probe(false,'scanner-runtime');probe(false,'production-compliant');for(let i=0;i<contract.productionNegativeCases;i++)probe(true,'production-negative-'+i);
  for(let i=0;i<c.exceptions.exceptions.length;i++){
   const ex=c.exceptions.exceptions[i],pods=parse(o.owners[i],'owner-'+ex.id).items;
   const pod=pods.find(p=>p.metadata.ownerReferences?.some(owner=>owner.uid===ex.owner.uid));requireValue('owner-'+ex.id,!!pod);
   // The original request builders access these fields before issuing mutations.
   requireValue('exception-containers-'+ex.id,Array.isArray(pod.spec.containers));
   probe(false,'exception-allow-'+ex.id);probe(true,'exception-wrong-owner-'+ex.id);
   requireValue('exception-container-'+ex.id,[...(pod.spec.initContainers??[]),...pod.spec.containers].some(x=>x.name===ex.container));
   probe(true,'exception-env-'+ex.id);
   if(ex.id==='sonarInit'){requireValue('exception-script-volume',!!pod.spec.volumes.find(x=>x.name==='init-sysctl').configMap);probe(true,'exception-script-'+ex.id);}
   if(ex.id==='falco')requireValue('exception-cap-list',Array.isArray(pod.spec.containers[0].securityContext.capabilities.add));
   else if(ex.id!=='nodeExporter')requireValue('exception-extra-container',!!pod.spec.containers[0]);
   probe(true,'exception-extra-'+ex.id);
  }
  const inventory=o.workloads;command(inventory,'workloads',true);const items=JSON.parse(inventory.stdout).items;
  const audit=frozenWorkloadAudit(items);
  requireValue('admission-report-write',o.admissionReportWriteSucceeded===true);
  return {status:'PASS',decision:'PASS',checks,auditResourceCount:audit.length,workloadAudit:audit,rawEvidence:structuredClone(raw)};
 }catch(error){return {status:'FAIL',decision:'FAIL',reason:error.message,checks,rawEvidence:structuredClone(raw)};}
}
