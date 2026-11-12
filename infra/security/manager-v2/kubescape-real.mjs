// Kubescape V2 candidate runner: real, controlled cluster posture audit.
// Drives the pinned Kubescape 4.0.17 binary against the live cluster through
// the allowlisted restricted-SSH wrapper on devops (security-kubescape): the
// entry executes the unchanged frozen governance audit
// (infra/security/governance/kubescape.mjs) under its passive runtime-facts
// observer and returns the observation packet. The fact is shaped for the
// FROZEN Policy adapter (infra/security/policy/kubescape-parent.mjs): the
// adapter's AUDIT semantics are authoritative and never recomputed locally —
// a successful audit execution maps to PASS, findings stay an audit WARN
// disposition in runtimeFacts, and execution-integrity failures map to FAIL.
// The runner's oldDecision is the frozen adapter's own decision on the same
// raw observations, and Core re-evaluates once and compares.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {kubescapeParent} from '../policy/kubescape-parent.mjs';
import {summarizeKubescape,combineKubescape} from '../governance/kubescape-report.mjs';
const exec=promisify(execFile);export const kubescapeProjects=()=>JSON.parse(fs.readFileSync(new URL('./kubescape/projects.json',import.meta.url))).projects;
const key=path.join(os.homedir(),'.ssh/security-manager-v2-kubescape');
const state=new URL('../../../.devsecops/security-view-kubescape-linux-v1.json',import.meta.url);
export function buildKubescapeFact(packet){
 return {component:'kubescape',status:'success',raw:packet.raw};
}
export function kubescapeUiCase(project,scenarioId){
 const want=scenarioId==='clean'?false:scenarioId==='controlled-finding'?true:null;if(want===null)throw Error('KUBESCAPE_SCENARIO_NOT_AUTHORIZED');
 const hit=Object.entries(project.cases).find(([,c])=>Boolean(c.violating)===want);if(!hit)throw Error('KUBESCAPE_SCENARIO_NOT_AUTHORIZED');return hit[0];
}
export function kubescapeBlockedReason(){
 try{const s=fs.lstatSync(key);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))return 'KUBESCAPE_SSH_KEY_NOT_CONFIGURED';}catch{return 'KUBESCAPE_SSH_KEY_NOT_CONFIGURED';}
 try{const v=JSON.parse(fs.readFileSync(state));if(v.enabled===true&&v.consumed!==true)return null;}catch{}
 return 'KUBESCAPE_EXECUTION_NOT_ARMED';
}
export function kubescapeReady(){return kubescapeBlockedReason()===null;}
export function kubescapeSshTarget(env=process.env){
 const host=env.KUBESCAPE_SSH_HOST??JSON.parse(fs.readFileSync(new URL('./kubescape/runner.json',import.meta.url))).sshHost;
 if(host!=='192.168.1.58')throw Error('KUBESCAPE_SSH_HOST_NOT_AUTHORIZED');
 return 'security-kubescape@'+host;
}
function scannerStarted(stages){return Array.isArray(stages)&&stages.some(s=>s?.stage==='SCAN_STARTED');}
function diagnosticFailure(message,code,runId,stages){
 const f=Error(message);f.code=code;
 f.candidateEvidence={kind:'KubescapeExecutionDiagnostic',diagnostic:{error:code,stage:'RESTRICTED_SSH_RUNNER',scannerStarted:scannerStarted(stages)},diagnosticRunId:runId,rawReportDigest:null};
 return f;
}
export function kubescapeScanSummaries(packet){
 const raw=packet.raw,o=raw?.observations;
 if(!o||!Array.isArray(o.scans)||o.scans.length!==4)throw Error('RUNNER_REPORT_ERROR');
 const pairs=[['cluster','nsa'],['yaml','nsa'],['cluster','cis-v1.12.0'],['yaml','cis-v1.12.0']];
 return o.scans.map((s,i)=>{
  let data;try{data=JSON.parse(s.report?.value);}catch{throw Error('RUNNER_REPORT_ERROR');}
  const summary=summarizeKubescape(data,pairs[i][0],pairs[i][1]);
  const violatingFindings=summary.resourceControlFindings.filter(f=>String(f.resourceId).includes('kubescape-v2-test'));
  return {...summary,violatingFindings};
 });
}
export function buildKubescapeRuntimeFacts(packet,runId){
 const scans=kubescapeScanSummaries(packet);
 const counts=combineKubescape(scans);
 const violatingFindings=scans.flatMap(s=>s.violatingFindings.map(f=>({scope:s.scope,framework:s.framework,...f})));
 return {kind:'RestrictedLinuxKubescape',projectId:packet.projectId,caseId:packet.caseId,toolVersion:packet.toolVersion,toolSha256:packet.toolSha256,gateStatus:packet.gate?.status??null,scans:scans.map(({resourceControlFindings,...s})=>s),counts,findings:counts.findings,failedControls:counts.failedControls,highRiskFindings:counts.highRiskFindings,auditDisposition:counts.findings?'WARN':'NO_FINDINGS',violatingFindings,violating:packet.violating??null,stages:packet.stages,classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId};
}
export function buildKubescapeEvidenceRefs(packet,project,runId){
 return [{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:packet.caseId,toolVersion:packet.toolVersion,gateStatus:packet.gate?.status??null,findings:packet.gate?.findings??null}];
}
export function validateKubescapePacket(x,{projectId,runId,project}){
 const kase=project.cases[x?.caseId];
 if(x.kind!=='RestrictedLinuxKubescape'||x.projectId!==projectId||x.runId!==runId||!kase||x.uid!==project.uid||x.gid!==project.gid||x.groups.some(g=>g!==project.gid)||!x.noNewPrivs||x.toolVersion!==project.toolVersion||x.toolSha256!==project.toolSha256||x.exitCode!==0||x.cleanup!=='VERIFIED'||x.gate?.status!=='success')throw Error('RUNNER_REPORT_ERROR');
 const lock=x.raw?.lock;
 if(!lock||lock.version!==project.toolVersion||lock.sha256!==project.toolSha256||lock.path!==project.toolPath||lock.artifactRoot!==project.toolArtifactRoot||!lock.artifacts||Object.keys(lock.artifacts).length!==Object.keys(project.toolArtifacts).length||Object.entries(project.toolArtifacts).some(([n,h])=>lock.artifacts[n]!==h))throw Error('RUNNER_REPORT_ERROR');
 if(typeof x.raw?.holder!=='string'||!x.raw.holder.startsWith('smv2-kubescape-'))throw Error('RUNNER_REPORT_ERROR');
 if(!x.stages.some(s=>s.stage==='SCAN_STARTED'&&Number.isInteger(s.pid))||!x.stages.some(s=>s.stage==='RUN_COMPLETED'))throw Error('RUNNER_REPORT_ERROR');
 if(kase.violating){const v=x.violating;if(!v||v.namespace!=='kubescape-v2-test'||v.created!==true||v.deleted!==true||v.verifiedGone!==true)throw Error('RUNNER_REPORT_ERROR');}
 kubescapeScanSummaries(x);
 return true;
}
export async function executeRealKubescape(plugin,input,{projectId,runId,signal}){
 keys(input,['targetId','caseId']);const p=kubescapeProjects()[projectId];if(!p||input.targetId!==p.targetId||!p.cases[input.caseId]||!kubescapeReady())throw Error('KUBESCAPE_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5',kubescapeSshTarget(),'audit-v1 '+projectId+' '+runId+' '+input.caseId];
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',args,{timeout:plugin.timeout,maxBuffer:64*1024*1024,signal,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){
  let code,stages;try{const o=JSON.parse(e.stdout);if(/^[A-Z_0-9]+$/.test(o?.error??''))code=o.error;stages=o?.stages;}catch{}
  if(code)throw diagnosticFailure('RUNNER_SCANNER_ERROR',code,runId,stages);
  if(signal?.aborted)throw diagnosticFailure('RUNNER_CANCELLED','KUBESCAPE_EXECUTION_CANCELLED',runId,stages);
  if(e.killed||e.signal)throw diagnosticFailure('RUNNER_TIMEOUT','KUBESCAPE_EXECUTION_TIMEOUT',runId,stages);
  throw diagnosticFailure('RUNNER_ERROR','KUBESCAPE_TRANSPORT_ERROR',runId,stages);
 }
 const x=packet;
 if(typeof x?.error==='string'&&/^[A-Z_0-9]+$/.test(x.error))throw diagnosticFailure('RUNNER_SCANNER_ERROR',x.error,runId,x.stages);
 validateKubescapePacket(x,{projectId,runId,project:p});
 const rawReport=JSON.stringify(x.raw);
 const fact=buildKubescapeFact(x);
 const oldDecision=kubescapeParent(structuredClone(x.raw)).decision;
 if(!['PASS','FAIL'].includes(oldDecision))throw Error('RUNNER_REPORT_ERROR');
 const runtimeFacts=buildKubescapeRuntimeFacts(x,runId);
 return freeze({rawReportBytesUtf8:rawReport,rawReportDigest:sha(rawReport),fact,factDigest:digest(fact),oldDecision,runtimeFacts,executionScope:'REAL_CONTROLLED_CLUSTER_AUDIT',evidenceRefs:buildKubescapeEvidenceRefs(x,p,runId),cleanup:{status:'VERIFIED',processExited:true}});
}
