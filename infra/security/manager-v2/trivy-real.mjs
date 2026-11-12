// Adapter for the existing Core/Policy/Artifact path; no policy decisions here.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile}from'node:child_process';import{promisify}from'node:util';
import{sha,digest,freeze}from'../summary-v2/codec.mjs';import{keys}from'./config.mjs';
const exec=promisify(execFile);export const trivyProjects=()=>JSON.parse(fs.readFileSync(new URL('./trivy/projects.json',import.meta.url))).projects;
const key=path.join(os.homedir(),'.ssh/security-manager-v2-trivy');
const state=new URL('../../../.devsecops/security-view-trivy-linux-v1.json',import.meta.url);
// Trivy CLI emits uppercase severities; the Policy engine contract accepts only
// canonical title-case values. UNKNOWN carries no scanner rating: it lands in
// the lowest rated bucket, which the frozen classifier already decides
// identically (WARN) and which every baseline level also decides identically.
const SEVERITIES=Object.freeze({CRITICAL:'Critical',HIGH:'High',MEDIUM:'Medium',LOW:'Low',UNKNOWN:'Low'});
export function normalizeTrivySeverity(value){const mapped=SEVERITIES[value];if(!mapped)throw Error('RUNNER_REPORT_ERROR');return mapped;}
export function buildTrivyFindings(rawReport){
 const findings=[];
 for(const r of rawReport?.Results??[]){const list=r?.Vulnerabilities??null;if(list!==null&&!Array.isArray(list))throw Error('RUNNER_REPORT_ERROR');for(const v of list??[])findings.push({id:v.VulnerabilityID,package:v.PkgName,version:v.InstalledVersion,severity:normalizeTrivySeverity(v.Severity),fixedVersion:v.FixedVersion??''});}
 return findings;
}
export function buildTrivyFact(packet,project){
 const image=project.registry+'/'+project.repository+'@'+project.platformDigest;
 return {component:'trivy',status:'success',raw:{findings:buildTrivyFindings(packet.rawReport),image,review:{image,entries:[]}}};
}
export function trivyBlockedReason(){
 try{const s=fs.lstatSync(key);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))return 'TRIVY_SSH_KEY_NOT_CONFIGURED';}catch{return 'TRIVY_SSH_KEY_NOT_CONFIGURED';}
 try{const v=JSON.parse(fs.readFileSync(state));if(v.enabled===true&&v.consumed!==true)return null;}catch{}
 return 'TRIVY_EXECUTION_NOT_ARMED';
}
export function trivyReady(){return trivyBlockedReason()===null;}
export function trivySshTarget(env=process.env){
 const host=env.TRIVY_SSH_HOST??JSON.parse(fs.readFileSync(new URL('./trivy/runner.json',import.meta.url))).sshHost;
 if(host!=='192.168.1.58')throw Error('TRIVY_SSH_HOST_NOT_AUTHORIZED');
 return 'security-trivy@'+host;
}
function scannerStarted(stages){return Array.isArray(stages)&&stages.some(s=>s?.stage==='SCANNER_STARTED');}
function diagnosticFailure(message,code,runId,stages){
 const f=Error(message);f.code=code;
 f.candidateEvidence={kind:'TrivyExecutionDiagnostic',diagnostic:{error:code,stage:'RESTRICTED_SSH_RUNNER',scannerStarted:scannerStarted(stages)},diagnosticRunId:runId,rawReportDigest:null};
 return f;
}
export async function executeRealTrivy(plugin,input,{projectId,runId,signal}){
 keys(input,['targetId']);const p=trivyProjects()[projectId];if(!p||input.targetId!==p.targetId||!trivyReady())throw Error('TRIVY_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5',trivySshTarget(),'scan-v1 '+projectId+' '+runId];
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',args,{timeout:210000,maxBuffer:3*1024*1024,signal,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){
  let code,stages;try{const o=JSON.parse(e.stdout);if(/^[A-Z_]+$/.test(o?.error??''))code=o.error;stages=o?.stages;}catch{}
  if(code)throw diagnosticFailure('RUNNER_SCANNER_ERROR',code,runId,stages);
  if(signal?.aborted)throw diagnosticFailure('RUNNER_CANCELLED','TRIVY_EXECUTION_CANCELLED',runId,stages);
  if(e.killed||e.signal)throw diagnosticFailure('RUNNER_TIMEOUT','TRIVY_EXECUTION_TIMEOUT',runId,stages);
  throw diagnosticFailure('RUNNER_ERROR','TRIVY_TRANSPORT_ERROR',runId,stages);
 }
 const x=packet;
 if(typeof x?.error==='string'&&/^[A-Z_]+$/.test(x.error))throw diagnosticFailure('RUNNER_SCANNER_ERROR',x.error,runId,x.stages);
 if(x.kind!=='RestrictedLinuxTrivy'||x.projectId!==projectId||x.runId!==runId||x.uid!==p.uid||x.gid!==p.gid||x.groups.some(g=>g!==p.gid)||!x.noNewPrivs||x.indexDigest!==p.indexDigest||x.platformDigest!==p.platformDigest||x.toolSha256!==p.toolSha256||x.toolVersion!=='0.76.2'||x.exitCode!==0||!x.stages.some(s=>s.stage==='SCANNER_STARTED'&&Number.isInteger(s.pid))||!x.stages.some(s=>s.stage==='RUN_COMPLETED'))throw Error('RUNNER_REPORT_ERROR');
 const raw=JSON.stringify(x.rawReport);if(sha(raw)!==x.rawReportSha256)throw Error('RUNNER_REPORT_ERROR');
 const fact=buildTrivyFact(x,p);if(fact.raw.findings.length!==x.findingCount)throw Error('RUNNER_REPORT_ERROR');
 const {rawReport,...runtimeFacts}=x;runtimeFacts.classification='REAL_CONTROLLED_EXECUTION';
 return freeze({rawReportBytesUtf8:raw,rawReportDigest:sha(raw),fact,factDigest:digest(fact),runtimeFacts,executionScope:'REAL_NON_PRODUCTION_IMAGE_SCAN',evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',runId,indexDigest:p.indexDigest,platformDigest:p.platformDigest,nativeReportSha256:x.nativeReportSha256}],cleanup:{status:'VERIFIED',processExited:true}});
}
