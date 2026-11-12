// Adapter for the existing Core/Policy/Artifact path; no policy decisions here.
// The frozen Policy engine evaluates the normalized admission observation via
// its existing kyverno-admission branch (infra/security/policy/kyverno-evidence.mjs):
// gate semantics are expectedDenial=false, so an admitted workload maps to
// PASS and a Kyverno-denied workload maps to FAIL.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
const exec=promisify(execFile);export const kyvernoProjects=()=>JSON.parse(fs.readFileSync(new URL('./kyverno/projects.json',import.meta.url))).projects;
const key=path.join(os.homedir(),'.ssh/security-manager-v2-kyverno');
const state=new URL('../../../.devsecops/security-view-kyverno-linux-v1.json',import.meta.url);
export function buildKyvernoFact(packet,project){
 const kase=project.cases[packet.caseId];
 const raw={expectedDenial:false,result:{allowed:packet.allowed,diagnostic:packet.diagnostic},caseId:packet.caseId,namespace:packet.namespace,policy:packet.policy,policyName:packet.policy,image:kase.image,projectTarget:project.targetId};
 return {component:'kyverno-admission',status:'success',raw};
}
export function kyvernoUiCase(project,scenarioId){
 const want=scenarioId==='clean'?true:scenarioId==='controlled-finding'?false:null;if(want===null)throw Error('KYVERNO_SCENARIO_NOT_AUTHORIZED');
 const hit=Object.entries(project.cases).find(([,c])=>c.expectedAllowed===want);if(!hit)throw Error('KYVERNO_SCENARIO_NOT_AUTHORIZED');return hit[0];
}
export function kyvernoBlockedReason(){
 try{const s=fs.lstatSync(key);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))return 'KYVERNO_SSH_KEY_NOT_CONFIGURED';}catch{return 'KYVERNO_SSH_KEY_NOT_CONFIGURED';}
 try{const v=JSON.parse(fs.readFileSync(state));if(v.enabled===true&&v.consumed!==true)return null;}catch{}
 return 'KYVERNO_EXECUTION_NOT_ARMED';
}
export function kyvernoReady(){return kyvernoBlockedReason()===null;}
export function kyvernoSshTarget(env=process.env){
 const host=env.KYVERNO_SSH_HOST??JSON.parse(fs.readFileSync(new URL('./kyverno/runner.json',import.meta.url))).sshHost;
 if(host!=='192.168.1.58')throw Error('KYVERNO_SSH_HOST_NOT_AUTHORIZED');
 return 'security-kyverno@'+host;
}
function scannerStarted(stages){return Array.isArray(stages)&&stages.some(s=>s?.stage==='ADMISSION_STARTED');}
function diagnosticFailure(message,code,runId,stages){
 const f=Error(message);f.code=code;
 f.candidateEvidence={kind:'KyvernoExecutionDiagnostic',diagnostic:{error:code,stage:'RESTRICTED_SSH_RUNNER',scannerStarted:scannerStarted(stages)},diagnosticRunId:runId,rawReportDigest:null};
 return f;
}
export function buildKyvernoRuntimeFacts(packet,runId){
 const {diagnostic,stages,...rest}=packet;
 return {...rest,stages,diagnosticSha256:sha(packet.diagnostic),classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId};
}
export function buildKyvernoEvidenceRefs(packet,project,runId){
 return [{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:packet.caseId,image:project.cases[packet.caseId].image,policy:packet.policy,namespace:packet.namespace,allowed:packet.allowed}];
}
export function validateKyvernoPacket(x,{projectId,runId,project}){
 const kase=project.cases[x?.caseId];
 if(x.kind!=='RestrictedLinuxKyverno'||x.projectId!==projectId||x.runId!==runId||!kase||x.uid!==project.uid||x.gid!==project.gid||x.groups.some(g=>g!==project.gid)||!x.noNewPrivs||x.namespace!==project.namespace||x.policy!==project.policy||x.image!==kase.image||x.toolSha256!==project.toolSha256||x.toolVersion!=='1.36.1'||typeof x.allowed!=='boolean'||x.exitCode!==(x.allowed?0:1)||typeof x.diagnostic!=='string'||x.diagnostic.length>1500||x.cleanup!=='VERIFIED'||!x.stages.some(s=>s.stage==='ADMISSION_STARTED'&&Number.isInteger(s.pid))||!x.stages.some(s=>s.stage==='RUN_COMPLETED'))throw Error('RUNNER_REPORT_ERROR');
 if(kase.realCreate){const r=x.realCreate;if(!r||r.attempted!==true||r.created!==true||r.deleted!==true||r.verifiedGone!==true)throw Error('RUNNER_REPORT_ERROR');}
 return true;
}
export async function executeRealKyverno(plugin,input,{projectId,runId,signal}){
 keys(input,['targetId','caseId']);const p=kyvernoProjects()[projectId];if(!p||input.targetId!==p.targetId||!p.cases[input.caseId]||!kyvernoReady())throw Error('KYVERNO_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5',kyvernoSshTarget(),'admit-v1 '+projectId+' '+runId+' '+input.caseId];
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',args,{timeout:plugin.timeout,maxBuffer:3*1024*1024,signal,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){
  let code,stages;try{const o=JSON.parse(e.stdout);if(/^[A-Z_]+$/.test(o?.error??''))code=o.error;stages=o?.stages;}catch{}
  if(code)throw diagnosticFailure('RUNNER_SCANNER_ERROR',code,runId,stages);
  if(signal?.aborted)throw diagnosticFailure('RUNNER_CANCELLED','KYVERNO_EXECUTION_CANCELLED',runId,stages);
  if(e.killed||e.signal)throw diagnosticFailure('RUNNER_TIMEOUT','KYVERNO_EXECUTION_TIMEOUT',runId,stages);
  throw diagnosticFailure('RUNNER_ERROR','KYVERNO_TRANSPORT_ERROR',runId,stages);
 }
 const x=packet;
 if(typeof x?.error==='string'&&/^[A-Z_]+$/.test(x.error))throw diagnosticFailure('RUNNER_SCANNER_ERROR',x.error,runId,x.stages);
 validateKyvernoPacket(x,{projectId,runId,project:p});
 const rawText=JSON.stringify(x);
 const fact=buildKyvernoFact(x,p);
 const runtimeFacts=buildKyvernoRuntimeFacts(x,runId);
 return freeze({rawReportBytesUtf8:rawText,rawReportDigest:sha(rawText),fact,factDigest:digest(fact),runtimeFacts,executionScope:'REAL_NON_PRODUCTION_CLUSTER_ADMISSION',evidenceRefs:buildKyvernoEvidenceRefs(x,p,runId),cleanup:{status:'VERIFIED',processExited:true}});
}
