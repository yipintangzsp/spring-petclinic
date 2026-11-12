// SonarQube V2 candidate runner: real, controlled quality-gate execution.
// Drives the live SonarQube server (pinned 26.3.0.120487) through the
// allowlisted restricted-SSH wrapper on devops (security-sonar): either a
// fresh sonar-scanner analysis of a pinned candidate source, or a fetch of
// the latest completed analysis of a candidate project the token user owns.
// The result is shaped for the FROZEN Policy adapter
// (infra/security/policy/sonar-evidence.mjs): the server Quality Gate is
// authoritative, never recomputed locally. The runner's oldDecision is the
// frozen adapter's own decision on the same raw task/gate payloads, and
// Core re-evaluates once and compares.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {sonarDecision} from '../policy/sonar-evidence.mjs';
const exec=promisify(execFile);export const sonarProjects=()=>JSON.parse(fs.readFileSync(new URL('./sonar/projects.json',import.meta.url))).projects;
const key=path.join(os.homedir(),'.ssh/security-manager-v2-sonar');
const state=new URL('../../../.devsecops/security-view-sonar-linux-v1.json',import.meta.url);
export function buildSonarRaw(packet){
 return {task:{task:packet.task},gate:{projectStatus:packet.gate},binding:{projectKey:packet.componentKey,taskId:packet.task.id,requestedAnalysisId:packet.task.analysisId}};
}
export function buildSonarFact(packet){
 return {component:'sonarqube',status:'success',raw:buildSonarRaw(packet)};
}
export function sonarUiCase(project,scenarioId){
 const want=scenarioId==='clean'?'OK':scenarioId==='controlled-finding'?'ERROR':null;if(want===null)throw Error('SONAR_SCENARIO_NOT_AUTHORIZED');
 const hit=Object.entries(project.cases).find(([,c])=>c.expectedGate===want);if(!hit)throw Error('SONAR_SCENARIO_NOT_AUTHORIZED');return hit[0];
}
export function sonarBlockedReason(){
 try{const s=fs.lstatSync(key);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))return 'SONAR_SSH_KEY_NOT_CONFIGURED';}catch{return 'SONAR_SSH_KEY_NOT_CONFIGURED';}
 try{const v=JSON.parse(fs.readFileSync(state));if(v.enabled===true&&v.consumed!==true)return null;}catch{}
 return 'SONAR_EXECUTION_NOT_ARMED';
}
export function sonarReady(){return sonarBlockedReason()===null;}
export function sonarSshTarget(env=process.env){
 const host=env.SONAR_SSH_HOST??JSON.parse(fs.readFileSync(new URL('./sonar/runner.json',import.meta.url))).sshHost;
 if(host!=='192.168.1.58')throw Error('SONAR_SSH_HOST_NOT_AUTHORIZED');
 return 'security-sonar@'+host;
}
function scannerStarted(stages){return Array.isArray(stages)&&stages.some(s=>s?.stage==='SCANNER_STARTED');}
function diagnosticFailure(message,code,runId,stages){
 const f=Error(message);f.code=code;
 f.candidateEvidence={kind:'SonarExecutionDiagnostic',diagnostic:{error:code,stage:'RESTRICTED_SSH_RUNNER',scannerStarted:scannerStarted(stages)},diagnosticRunId:runId,rawReportDigest:null};
 return f;
}
export function buildSonarRuntimeFacts(packet,runId){
 const {task,gate,stages,...rest}=packet;
 return {...rest,stages,taskId:task.id,analysisId:task.analysisId,gateStatus:gate.status,conditions:gate.conditions,classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId};
}
export function buildSonarEvidenceRefs(packet,project,runId){
 return [{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:packet.caseId,componentKey:packet.componentKey,analysisId:packet.task.analysisId,gateStatus:packet.gate.status}];
}
export function validateSonarPacket(x,{projectId,runId,project}){
 const kase=project.cases[x?.caseId];
 const expectedComponent=!kase?null:kase.componentKey??(kase.componentKeyPrefix?kase.componentKeyPrefix+runId.slice(4,12):null);
 if(x.kind!=='RestrictedLinuxSonar'||x.projectId!==projectId||x.runId!==runId||!kase||x.uid!==project.uid||x.gid!==project.gid||x.groups.some(g=>g!==project.gid)||!x.noNewPrivs||x.componentKey!==expectedComponent||x.serverVersion!==project.serverVersion||x.toolVersion!=='7.2.0.5079'||x.toolSha256!==project.toolSha256||x.exitCode!==0||x.cleanup!=='VERIFIED'||!Number.isInteger(x.issuesTotal)||x.issuesTotal<0||typeof x.measures!=='object'||x.measures===null)throw Error('RUNNER_REPORT_ERROR');
 if(!['scan','fetch'].includes(x.mode)||!x.task||x.task.componentKey!==x.componentKey||x.task.status!=='SUCCESS'||typeof x.task.id!=='string'||!x.task.id||typeof x.task.analysisId!=='string'||!x.task.analysisId)throw Error('RUNNER_REPORT_ERROR');
 if(!x.gate||!['OK','ERROR'].includes(x.gate.status)||!Array.isArray(x.gate.conditions))throw Error('RUNNER_REPORT_ERROR');
 for(const c of x.gate.conditions){if(typeof c.metricKey!=='string'||!c.metricKey||!['OK','ERROR','NO_VALUE'].includes(c.status)||typeof c.comparator!=='string'||typeof c.errorThreshold!=='string'||typeof c.actualValue!=='string')throw Error('RUNNER_REPORT_ERROR');}
 if(!x.stages.some(s=>s.stage==='RUN_COMPLETED'))throw Error('RUNNER_REPORT_ERROR');
 if(x.mode==='scan'){if(!Array.isArray(x.scans)||x.scans.length<1||x.scans.at(-1).ceTaskId!==x.task.id||!x.stages.some(s=>s.stage==='SCANNER_STARTED'&&Number.isInteger(s.pid)))throw Error('RUNNER_REPORT_ERROR');}
 else if(!Array.isArray(x.scans)||x.scans.length!==0||!x.stages.some(s=>s.stage==='GATE_FETCH_STARTED'))throw Error('RUNNER_REPORT_ERROR');
 return true;
}
export async function executeRealSonar(plugin,input,{projectId,runId,signal}){
 keys(input,['targetId','caseId']);const p=sonarProjects()[projectId];if(!p||input.targetId!==p.targetId||!p.cases[input.caseId]||!sonarReady())throw Error('SONAR_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5',sonarSshTarget(),'gate-v1 '+projectId+' '+runId+' '+input.caseId];
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',args,{timeout:plugin.timeout,maxBuffer:3*1024*1024,signal,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){
  let code,stages;try{const o=JSON.parse(e.stdout);if(/^[A-Z_0-9]+$/.test(o?.error??''))code=o.error;stages=o?.stages;}catch{}
  if(code)throw diagnosticFailure('RUNNER_SCANNER_ERROR',code,runId,stages);
  if(signal?.aborted)throw diagnosticFailure('RUNNER_CANCELLED','SONAR_EXECUTION_CANCELLED',runId,stages);
  if(e.killed||e.signal)throw diagnosticFailure('RUNNER_TIMEOUT','SONAR_EXECUTION_TIMEOUT',runId,stages);
  throw diagnosticFailure('RUNNER_ERROR','SONAR_TRANSPORT_ERROR',runId,stages);
 }
 const x=packet;
 if(typeof x?.error==='string'&&/^[A-Z_0-9]+$/.test(x.error))throw diagnosticFailure('RUNNER_SCANNER_ERROR',x.error,runId,x.stages);
 validateSonarPacket(x,{projectId,runId,project:p});
 const rawReport=JSON.stringify({task:{task:x.task},gate:{projectStatus:x.gate}});
 const fact=buildSonarFact(x);
 const oldDecision=sonarDecision(fact.raw).decision;
 const runtimeFacts=buildSonarRuntimeFacts(x,runId);
 return freeze({rawReportBytesUtf8:rawReport,rawReportDigest:sha(rawReport),fact,factDigest:digest(fact),oldDecision,runtimeFacts,executionScope:'REAL_CONTROLLED_QUALITY_GATE',evidenceRefs:buildSonarEvidenceRefs(x,p,runId),cleanup:{status:'VERIFIED',processExited:true}});
}
