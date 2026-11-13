import {summarizeKubescape,combineKubescape} from '../governance/kubescape-report.mjs';
import fs from 'node:fs';import crypto from 'node:crypto';
export function kubescapeParent(raw){
 const binding=JSON.parse(fs.readFileSync(new URL('./versions/kubescape-parent-baseline-v1.json',import.meta.url)));
 for(const [p,hash]of Object.entries(binding.sourceHashes)){const file=new URL('../'+p.replace('infra/security/',''),import.meta.url);if(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==hash)throw Error('POLICY_ERROR: Kubescape frozen source changed');}
 if(!raw?.lock||!raw?.observations)return {status:'NOT_CONFIGURED',decision:null,reason:'Frozen execution observations missing'};
 const o=raw.observations,checks=[],scans=[];let tempCreated=false;
 const must=(id,ok)=>{checks.push({id,passed:!!ok});if(!ok)throw Error(id);};
 const read=(r,id)=>{must(id+'-read',!!r&&!r.error);return r.value;};
 const command=(r,id,allowed=[0])=>{must(id+'-command',!!r&&!r.error&&allowed.includes(r.status));return r.stdout;};
 let failure;
 try{
  must('lock-read',o.lockReadSucceeded===true);must('output-dir',o.outputDirSucceeded===true);must('source-read',o.sourceReadSucceeded===true);
  must('binary-hash',read(o.hashes[raw.lock.path],'binary')===raw.lock.sha256);
  for(const [name,hash]of Object.entries(raw.lock.artifacts))must('artifact-'+name,read(o.hashes[raw.lock.artifactRoot+'/'+name],name)===hash);
  const lease=JSON.parse(command(o.lease,'lease'));must('lease-holder',lease.spec.holderIdentity===raw.holder);
  must('temp-create',o.tempCreateSucceeded===true);tempCreated=true;must('temp-mode',o.tempChmodSucceeded===true);
  command(o.server,'context').trim();Buffer.from(JSON.parse(command(o.ca,'ca')).data['ca.crt']).toString('base64');command(o.token,'token').trim();
  must('kubeconfig-write',o.configWriteSucceeded===true);
  const denied=command(o.secretReadCheck,'deny-secret',[0,1]).trim(),write=command(o.businessWriteCheck,'deny-business-write',[0,1]).trim();must('least-privilege',denied==='no'&&write==='no');
  for(let i=0;i<4;i++){
   const pair=binding.scans[i],scan=o.scans?.[i];must('scan-'+i+'-observed',!!scan);
   must('scan-'+i+'-log-write',scan.logWriteSucceeded===true);
   must('scan-'+i+'-execution',!!scan.command&&!scan.command.error&&scan.command.status===0);
   const data=JSON.parse(read(scan.report,'report-'+i));const summary=summarizeKubescape(data,pair.scope,pair.framework);
   // Original also hashes bytes after parsing/summarizing each native report.
   read(scan.hash,'report-hash-'+i);scans.push(summary);
  }
 }catch(error){failure=error.message;}
 // finally behavior can fail even after successful scans; cleanup is not a risk finding.
 if(tempCreated&&o.cleanupSucceeded!==true)failure='temporary-kubeconfig-cleanup';
 // In the original, a throwing cleanup prevents report write, and a throwing report write fails.
 if(!failure||failure!=='temporary-kubeconfig-cleanup')if(o.finalReportWriteSucceeded!==true)failure='final-report-write';
 if(failure)return {status:'FAIL',decision:'FAIL',reason:failure,checks,rawEvidence:structuredClone(raw)};
 const counts=combineKubescape(scans);
 return {status:'PASS',decision:'PASS',executionStatus:'success',auditMode:'AUDIT',auditDisposition:counts.findings||counts.failedControls?'WARN':'NO_FINDINGS',scans,counts,checks,rawEvidence:structuredClone(raw)};
}
