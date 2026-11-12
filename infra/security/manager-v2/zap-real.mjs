// ZAP V2 candidate runner: real, controlled passive DAST execution.
// Drives the pinned ZAP 2.17.0 installation on devops through the
// allowlisted restricted-SSH wrapper (security-zap): the wrapper starts a
// code-owned loopback fixture target, runs a fixed automation plan
// (requestor GET + passiveScan-wait + traditional-json report; no spider,
// no active scan, no external target), terminates the fixture and verifies
// cleanup before returning the native report bytes.
// The result is shaped for the FROZEN Policy adapter: engine component
// 'zap' consumes {report, context, approved} through the existing
// classifyZap classifier (infra/security/zap-policy.mjs) — unconfirmed
// High alerts stay WARN at standard level and FAIL at strict level by the
// platform's own level table; the runner never recomputes or relabels
// alerts. The runner's oldDecision is the frozen engine's own decision on
// the same fact at the case-pinned policy level, and Core re-evaluates
// once and compares.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {evaluate} from '../policy/engine.mjs';
const exec=promisify(execFile);export const zapProjects=()=>JSON.parse(fs.readFileSync(new URL('./zap/projects.json',import.meta.url))).projects;
export const zapConfirmations=()=>JSON.parse(fs.readFileSync(new URL('../zap-confirmations.json',import.meta.url)));
const key=path.join(os.homedir(),'.ssh/security-manager-v2-zap');
const state=new URL('../../../.devsecops/security-view-zap-linux-v1.json',import.meta.url);
export function buildZapRaw(packet){
 return {report:JSON.parse(packet.reportText),context:{targetImage:packet.targetImage,reportSha256:packet.reportSha256},approved:zapConfirmations()};
}
export function buildZapFact(packet){
 return {component:'zap',status:'success',raw:buildZapRaw(packet)};
}
export function zapDecisionAt(fact,policyLevel){
 return evaluate(fact,{policyVersion:'baseline-v1',securityLevel:policyLevel,mode:'enforce'}).decision;
}
export function zapUiCase(project,scenarioId){
 const want=scenarioId==='clean'?['standard','PASS']:scenarioId==='controlled-finding'?['strict','FAIL']:null;if(want===null)throw Error('ZAP_SCENARIO_NOT_AUTHORIZED');
 const hit=Object.entries(project.cases).find(([,c])=>c.expectedDecision[want[0]]===want[1]);if(!hit)throw Error('ZAP_SCENARIO_NOT_AUTHORIZED');return hit[0];
}
export function zapBlockedReason(){
 try{const s=fs.lstatSync(key);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))return 'ZAP_SSH_KEY_NOT_CONFIGURED';}catch{return 'ZAP_SSH_KEY_NOT_CONFIGURED';}
 try{const v=JSON.parse(fs.readFileSync(state));if(v.enabled===true&&v.consumed!==true)return null;}catch{}
 return 'ZAP_EXECUTION_NOT_ARMED';
}
export function zapReady(){return zapBlockedReason()===null;}
export function zapSshTarget(env=process.env){
 const host=env.ZAP_SSH_HOST??JSON.parse(fs.readFileSync(new URL('./zap/runner.json',import.meta.url))).sshHost;
 if(host!=='192.168.1.58')throw Error('ZAP_SSH_HOST_NOT_AUTHORIZED');
 return 'security-zap@'+host;
}
function scannerStarted(stages){return Array.isArray(stages)&&stages.some(s=>s?.stage==='SCAN_STARTED');}
function diagnosticFailure(message,code,runId,stages){
 const f=Error(message);f.code=code;
 f.candidateEvidence={kind:'ZapExecutionDiagnostic',diagnostic:{error:code,stage:'RESTRICTED_SSH_RUNNER',scannerStarted:scannerStarted(stages)},diagnosticRunId:runId,rawReportDigest:null};
 return f;
}
export function buildZapRuntimeFacts(packet,runId){
 const {reportText,...rest}=packet;
 return {...rest,classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId};
}
export function buildZapEvidenceRefs(packet,project,runId){
 return [{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:packet.caseId,target:packet.target,targetImage:packet.targetImage,reportSha256:packet.reportSha256,alertsTotal:packet.alertsTotal}];
}
export function summarizeZapReport(report){
 const alerts=[],riskCounts={'0':0,'1':0,'2':0,'3':0};
 for(const s of report.site)for(const a of s.alerts??[]){
  const rc=Number(a.riskcode);if(![0,1,2,3].includes(rc))throw Error('RUNNER_REPORT_ERROR');
  riskCounts[String(rc)]++;alerts.push({pluginid:String(a.pluginid),name:a.name,riskcode:rc,count:a.count});
 }
 alerts.sort((x,y)=>x.pluginid.localeCompare(y.pluginid)||x.riskcode-y.riskcode);
 return {alerts,riskCounts};
}
export function validateZapPacket(x,{projectId,runId,project}){
 const kase=project.cases[x?.caseId];
 if(x.kind!=='RestrictedLinuxZap'||x.projectId!==projectId||x.runId!==runId||!kase||x.uid!==project.uid||x.gid!==project.gid||x.groups.some(g=>g!==project.gid)||!x.noNewPrivs||x.target!==kase.target||x.targetImage!==kase.targetImage||x.toolVersion!=='2.17.0'||x.toolSha256!==project.toolSha256||x.exitCode!==0||x.cleanup!=='VERIFIED')throw Error('RUNNER_REPORT_ERROR');
 if(typeof x.reportText!=='string'||x.reportText.length>2*1024*1024||sha(x.reportText)!==x.reportSha256)throw Error('RUNNER_REPORT_ERROR');
 let report;try{report=JSON.parse(x.reportText);}catch{throw Error('RUNNER_REPORT_ERROR');}
 const port=new URL(kase.target).port;
 if(!Array.isArray(report.site)||!report.site.length||report.site.some(s=>s['@host']!=='127.0.0.1'||String(s['@port'])!==port))throw Error('RUNNER_REPORT_ERROR');
 const sum=summarizeZapReport(report);
 if(JSON.stringify(sum.alerts)!==JSON.stringify(x.alerts)||JSON.stringify(sum.riskCounts)!==JSON.stringify(x.riskCounts)||x.alertsTotal!==sum.alerts.length)throw Error('RUNNER_REPORT_ERROR');
 if(!x.stages.some(s=>s.stage==='SCAN_STARTED'&&Number.isInteger(s.pid))||!x.stages.some(s=>s.stage==='RUN_COMPLETED'))throw Error('RUNNER_REPORT_ERROR');
 return report;
}
export async function executeRealZap(plugin,input,{projectId,runId,signal}){
 keys(input,['targetId','caseId','policyLevel']);const p=zapProjects()[projectId];if(!p||input.targetId!==p.targetId||!p.cases[input.caseId]||!p.cases[input.caseId].levels.includes(input.policyLevel)||!zapReady())throw Error('ZAP_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5',zapSshTarget(),'scan-v1 '+projectId+' '+runId+' '+input.caseId];
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',args,{timeout:plugin.timeout,maxBuffer:3*1024*1024,signal,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){
  let code,stages;try{const o=JSON.parse(e.stdout);if(/^[A-Z_0-9]+$/.test(o?.error??''))code=o.error;stages=o?.stages;}catch{}
  if(code)throw diagnosticFailure('RUNNER_SCANNER_ERROR',code,runId,stages);
  if(signal?.aborted)throw diagnosticFailure('RUNNER_CANCELLED','ZAP_EXECUTION_CANCELLED',runId,stages);
  if(e.killed||e.signal)throw diagnosticFailure('RUNNER_TIMEOUT','ZAP_EXECUTION_TIMEOUT',runId,stages);
  throw diagnosticFailure('RUNNER_ERROR','ZAP_TRANSPORT_ERROR',runId,stages);
 }
 const x=packet;
 if(typeof x?.error==='string'&&/^[A-Z_0-9]+$/.test(x.error))throw diagnosticFailure('RUNNER_SCANNER_ERROR',x.error,runId,x.stages);
 validateZapPacket(x,{projectId,runId,project:p});
 const fact=buildZapFact(x);
 const oldDecision=zapDecisionAt(fact,input.policyLevel);
 if(!['PASS','WARN','FAIL'].includes(oldDecision))throw Error('RUNNER_REPORT_ERROR');
 const runtimeFacts=buildZapRuntimeFacts(x,runId);
 return freeze({rawReportBytesUtf8:x.reportText,rawReportDigest:sha(x.reportText),fact,factDigest:digest(fact),oldDecision,runtimeFacts,executionScope:'REAL_CONTROLLED_PASSIVE_SCAN',evidenceRefs:buildZapEvidenceRefs(x,p,runId),cleanup:{status:'VERIFIED',processExited:true}});
}
