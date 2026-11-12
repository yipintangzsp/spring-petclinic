// SOPS V2 candidate runner: real, controlled secrets-gate validation.
// Drives the pinned sops 3.13.3 / age 1.3.2 toolchain on devops through the
// allowlisted restricted-SSH wrapper (security-sops): the wrapper generates
// a disposable age keypair per run, encrypts synthetic Secret fixtures for
// the four frozen secrets-gate targets, executes the gate observation flow
// (decrypt -> scope -> live compare -> fixture-store apply -> re-read ->
// fixture ACL permission matrix -> redacted report) against a file-backed
// fixture store, shreds the test key and removes the work directory before
// returning the observation packet. The production cluster, production
// ciphertext and production age keys are never touched (the frozen SOPS
// compatibility reviews established the production gate cannot be rerun
// against the live cluster safely); the fixture store is the documented
// equivalent validation surface, recorded in runtimeFacts.storeModel.
// The fact is shaped for the FROZEN Policy adapter: engine component
// 'sops' consumes the gate observations through sopsFacts/sopsDecision
// (infra/security/policy/sops-evidence.mjs) — PASS only when every frozen
// check passes, FAIL otherwise; the runner never recomputes a decision
// except the frozen engine's own evaluation used as oldDecision, which
// Core re-evaluates once and compares. Decrypted fixture values are
// synthetic public labels; no real secret material exists in this flow.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {evaluate} from '../policy/engine.mjs';
const exec=promisify(execFile);export const sopsProjects=()=>JSON.parse(fs.readFileSync(new URL('./sops/projects.json',import.meta.url))).projects;
const key=path.join(os.homedir(),'.ssh/security-manager-v2-sops');
const state=new URL('../../../.devsecops/security-view-sops-linux-v1.json',import.meta.url);
export function buildSopsRaw(packet){return packet.raw;}
export function buildSopsFact(packet){return {component:'sops',status:'success',raw:buildSopsRaw(packet)};}
export function sopsDecisionAt(fact){return evaluate(fact,{policyVersion:'baseline-v1',securityLevel:'standard',mode:'enforce'}).decision;}
export function sopsUiCase(project,scenarioId){
 const want=scenarioId==='clean'?'compliant':scenarioId==='controlled-finding'?'tampered-ciphertext':null;if(want===null)throw Error('SOPS_SCENARIO_NOT_AUTHORIZED');
 if(!project.cases[want])throw Error('SOPS_SCENARIO_NOT_AUTHORIZED');return want;
}
export function sopsBlockedReason(){
 try{const s=fs.lstatSync(key);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))return 'SOPS_SSH_KEY_NOT_CONFIGURED';}catch{return 'SOPS_SSH_KEY_NOT_CONFIGURED';}
 try{const v=JSON.parse(fs.readFileSync(state));if(v.enabled===true&&v.consumed!==true)return null;}catch{}
 return 'SOPS_EXECUTION_NOT_ARMED';
}
export function sopsReady(){return sopsBlockedReason()===null;}
export function sopsSshTarget(env=process.env){
 const host=env.SOPS_SSH_HOST??JSON.parse(fs.readFileSync(new URL('./sops/runner.json',import.meta.url))).sshHost;
 if(host!=='192.168.1.58')throw Error('SOPS_SSH_HOST_NOT_AUTHORIZED');
 return 'security-sops@'+host;
}
function scannerStarted(stages){return Array.isArray(stages)&&stages.some(s=>s?.stage==='GATE_STARTED');}
function diagnosticFailure(message,code,runId,stages){
 const f=Error(message);f.code=code;
 f.candidateEvidence={kind:'SopsExecutionDiagnostic',diagnostic:{error:code,stage:'RESTRICTED_SSH_RUNNER',scannerStarted:scannerStarted(stages)},diagnosticRunId:runId,rawReportDigest:null};
 return f;
}
export function buildSopsRuntimeFacts(packet,runId){
 const {raw,...rest}=packet;
 return {...rest,rawDigest:digest(raw),classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId};
}
export function buildSopsEvidenceRefs(packet,project,runId){
 return [{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:packet.caseId,toolVersion:packet.toolVersion,storeModel:packet.storeModel,cipherTargets:packet.cipherFacts.length}];
}
export function validateSopsPacket(x,{projectId,runId,project}){
 const kase=project.cases[x?.caseId];
 if(x.kind!=='RestrictedLinuxSops'||x.projectId!==projectId||x.runId!==runId||!kase||x.uid!==project.uid||x.gid!==project.gid||x.groups.some(g=>g!==project.gid)||!x.noNewPrivs||x.toolVersion!=='3.13.3'||x.toolSha256!==project.toolSha256||x.ageVersion!=='1.3.2'||x.ageSha256!==project.ageSha256||x.exitCode!==0||x.cleanup!=='VERIFIED'||x.storeModel!=='FILE_FIXTURE_STORE'||x.rbacModel!=='FIXTURE_STORE_ACL')throw Error('RUNNER_REPORT_ERROR');
 if(!Array.isArray(x.cipherFacts)||x.cipherFacts.length!==project.targets.length)throw Error('RUNNER_REPORT_ERROR');
 x.cipherFacts.forEach((c,i)=>{
  const [ns,name]=project.targets[i];
  if(c.namespace!==ns||c.name!==name||!/^[a-f0-9]{64}$/.test(c.encSha256)||!Number.isInteger(c.encBytes)||c.encBytes<1)throw Error('RUNNER_REPORT_ERROR');
  const masquerade=x.caseId==='plaintext-masquerade'&&name==='rabbitmq-client';
  if(masquerade?c.hasMac!==false||c.recipientCount!==0:c.hasMac!==true||c.recipientCount!==1)throw Error('RUNNER_REPORT_ERROR');
 });
 const raw=x.raw;
 if(!raw||raw.expectedTargetCount!==project.targets.length||!Array.isArray(raw.targets)||raw.targets.length!==project.targets.length||raw.readOnly!==false)throw Error('RUNNER_REPORT_ERROR');
 raw.targets.forEach((t,i)=>{const [ns,name]=project.targets[i];if(t.expected?.namespace!==ns||t.expected?.name!==name||!Number.isInteger(t.decrypt?.exitStatus)||typeof t.decrypt?.stdout!=='string')throw Error('RUNNER_REPORT_ERROR');});
 if(!x.stages.some(s=>s.stage==='GATE_STARTED'&&Number.isInteger(s.pid))||!x.stages.some(s=>s.stage==='RUN_COMPLETED'))throw Error('RUNNER_REPORT_ERROR');
 return raw;
}
export async function executeRealSops(plugin,input,{projectId,runId,signal}){
 keys(input,['targetId','caseId']);const p=sopsProjects()[projectId];if(!p||input.targetId!==p.targetId||!p.cases[input.caseId]||!sopsReady())throw Error('SOPS_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5',sopsSshTarget(),'validate-v1 '+projectId+' '+runId+' '+input.caseId];
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',args,{timeout:plugin.timeout,maxBuffer:4*1024*1024,signal,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){
  let code,stages;try{const o=JSON.parse(e.stdout);if(/^[A-Z_0-9]+$/.test(o?.error??''))code=o.error;stages=o?.stages;}catch{}
  if(code)throw diagnosticFailure('RUNNER_SCANNER_ERROR',code,runId,stages);
  if(signal?.aborted)throw diagnosticFailure('RUNNER_CANCELLED','SOPS_EXECUTION_CANCELLED',runId,stages);
  if(e.killed||e.signal)throw diagnosticFailure('RUNNER_TIMEOUT','SOPS_EXECUTION_TIMEOUT',runId,stages);
  throw diagnosticFailure('RUNNER_ERROR','SOPS_TRANSPORT_ERROR',runId,stages);
 }
 const x=packet;
 if(typeof x?.error==='string'&&/^[A-Z_0-9]+$/.test(x.error))throw diagnosticFailure('RUNNER_SCANNER_ERROR',x.error,runId,x.stages);
 validateSopsPacket(x,{projectId,runId,project:p});
 const rawReport=JSON.stringify(x.raw);
 const fact=buildSopsFact(x);
 const oldDecision=sopsDecisionAt(fact);
 if(!['PASS','FAIL'].includes(oldDecision))throw Error('RUNNER_REPORT_ERROR');
 const runtimeFacts=buildSopsRuntimeFacts(x,runId);
 return freeze({rawReportBytesUtf8:rawReport,rawReportDigest:sha(rawReport),fact,factDigest:digest(fact),oldDecision,runtimeFacts,executionScope:'REAL_CONTROLLED_FIXTURE_GATE',evidenceRefs:buildSopsEvidenceRefs(x,p,runId),cleanup:{status:'VERIFIED',processExited:true}});
}
