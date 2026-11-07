// Explicit local opt-in to the approved SSH identity and two fixed fixtures.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {verifyArtifact,verifyResult} from '../result.mjs';
import {digest,sha} from '../../summary-v2/codec.mjs';
const exec=promisify(execFile),sshDir=path.join(os.homedir(),'.ssh');
const key=path.join(sshDir,'security-manager-v2-gitleaks');
const known=path.join(sshDir,'known_hosts');
const optIn=new URL('../../../../.devsecops/security-view-gitleaks-linux-v1.json',import.meta.url);
const workspace='/var/tmp/security-manager-gitleaks-v2-linux-20261105';
const binarySha='db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d';
export const linuxHost='devops/192.168.64.11';
export const cleanIdentity='security-gitleaks (UID/GID 24021)';
const fault=code=>Object.assign(Error(code),{code});
function ownedFile(p,forbidden,maximum){
 const s=fs.lstatSync(p);
 return s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&!(s.mode&forbidden)&&s.size>0&&s.size<=maximum;
}
export function linuxReady(){
 try{return ownedFile(optIn,0o077,128)&&ownedFile(key,0o077,8192)&&ownedFile(known,0o022,1048576)&&
  fs.readFileSync(optIn,'utf8').trim()==='{"enabled":true}';}catch{return false;}
}
const args=['-F','/dev/null','-T','-n','-i',key,
 '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','PreferredAuthentications=publickey',
 '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes',
 '-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+known,'-o','GlobalKnownHostsFile=/dev/null',
 '-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
 '-o','ServerAliveInterval=4','-o','ServerAliveCountMax=2','security-gitleaks@192.168.64.11'];
function check(ok){if(!ok)throw fault('LINUX_RESULT_EVIDENCE_REJECTED');}
function decode(data){
 check(typeof data==='string'&&data.length<=175000&&/^[A-Za-z0-9+/]+={0,2}$/.test(data));
 const bytes=Buffer.from(data,'base64');check(bytes.toString('base64')===data&&bytes.length<=128*1024);return bytes;
}
export async function runLinuxGitleaks(scenarioId,runId,dir,signal,securityLevel='standard'){
 if(!['low','standard','strict'].includes(securityLevel))throw fault('INVALID_CANDIDATE_SECURITY_LEVEL');
 if(!linuxReady())throw fault('LINUX_GITLEAKS_NOT_CONFIGURED_BLOCKED');
 check(scenarioId==='clean'||scenarioId==='controlled-finding');
 const finding=scenarioId==='controlled-finding';
 check(/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(runId));
 let packet;
 try{
  const {stdout}=await exec('/usr/bin/ssh',[...args,(finding?'finding-v1 ':'clean-v1 ')+runId+' '+securityLevel],{signal,timeout:29000,maxBuffer:524288,env:{PATH:'/usr/bin:/bin',LANG:'C'}});
  packet=JSON.parse(stdout);
 }catch(e){
  let remoteCode;try{remoteCode=JSON.parse(e.stdout).error;}catch{}
  if(['LINUX_RESOURCE_BUDGET_BLOCKED','RESOURCE_STATE_UNKNOWN_BLOCKED','EXECUTION_BUSY','OUTPUT_BUDGET_EXHAUSTED',
   'EXECUTION_TIMEOUT','EXECUTION_OR_OUTPUT_REJECTED','DESCENDANT_CLEANUP_FAILED','PRODUCTION_AUTHORITY_READABLE'].includes(remoteCode))throw fault(remoteCode);
  throw fault('LINUX_GITLEAKS_TRANSPORT_ERROR');
 }
 return acceptLinuxGitleaksPacket(packet,scenarioId,runId,dir,securityLevel);
}
export async function runLinuxCommitSnapshot(context,runId,dir,signal,securityLevel='standard'){
 if(!linuxReady()||!/^[a-f0-9]{40}$/.test(context.commitSha)||!/^web-[a-f0-9-]{36}$/.test(runId)||!['low','standard','strict'].includes(securityLevel))throw fault('SOURCE_REQUEST_REJECTED');
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',[...args,'commit-v1 '+runId+' '+securityLevel],{signal,timeout:85000,maxBuffer:2*1024*1024,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}catch(e){let code;try{code=JSON.parse(e.stdout).error;}catch{}throw fault(/^(?:SOURCE_[A-Z_]+|RUNNER_[A-Z_]+|LINUX_RESOURCE_BUDGET_BLOCKED)$/.test(code??'')?code:'SOURCE_TRANSPORT_ERROR');}
 return acceptLinuxGitleaksPacket(packet,'commit-snapshot',runId,dir,securityLevel,context);
}
// The existing sealed-result validation is shared with the trusted Jenkins dispatcher.
// This function consumes facts; it never scans or evaluates Policy.
export function acceptLinuxGitleaksPacket(packet,scenarioId,runId,dir,securityLevel='standard',sourceContext=null){
 const commit=!!sourceContext;
 check(scenarioId==='clean'||scenarioId==='controlled-finding'||commit&&scenarioId==='commit-snapshot');
 check(/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(runId));
 const finding=scenarioId==='controlled-finding';
 check(packet?.schemaVersion===1&&packet.kind===(commit?'RestrictedLinuxGitleaksCommit':finding?'RestrictedLinuxGitleaksFinding':'RestrictedLinuxGitleaksClean')&&
  packet.runId===runId&&packet.scenarioId===scenarioId&&packet.executionHost===linuxHost);
 const r=packet.result,f=r?.runtimeFacts,i=f?.identity;verifyResult(r);check(['low','standard','strict'].includes(securityLevel)&&r.securityLevel===securityLevel&&r.policy?.securityLevel===securityLevel&&r.policy?.evaluation?.securityLevel===securityLevel);
 check(r.runId===runId&&r.pluginId==='gitleaks'&&r.projectId===(commit?sourceContext.projectId:finding?'java-fixture':'python-fixture')&&r.executionStatus==='COMPLETED'&&r.evaluationCount===1&&
  r.policyDecision===r.oldGateDecision&&(commit?['PASS','FAIL'].includes(r.policyDecision):r.policyDecision===(finding?'FAIL':'PASS'))&&packet.policyEvaluationCount===1&&packet.executionCounts?.scans===1);
 check(f.classification==='REAL_CONTROLLED_EXECUTION'&&f.validationRunId===runId&&(commit?f.sourceDir.path==='/var/tmp/security-manager-gitleaks-realcommit-20261107/outputs/source-'+runId+'/source':f.sourceDir.path===workspace+(finding?'/source-java':'/source-python'))&&
  f.tool.sha256===binarySha&&f.tool.version==='8.30.1'&&f.tool.observedVersion.replace(/^v/,'')==='8.30.1'&&(commit?[0,1].includes(f.command.exitStatus):f.command.exitStatus===(finding?1:0))&&
  f.command.signal===null&&r.cleanup?.processGroupGone===true);
 if(commit)check(f.sourceSnapshot?.sourceMode==='REAL_COMMIT_SNAPSHOT'&&f.sourceSnapshot.commitSha===sourceContext.commitSha&&f.sourceSnapshot.repository===sourceContext.sourceRepository&&/^[a-f0-9]{64}$/.test(f.sourceSnapshot.archiveSha256)&&/^[a-f0-9]{40}$/.test(f.sourceSnapshot.rootTreeOid)&&r.cleanup.sourceWorkspaceRemoved===true);
 check(i.uid===24021&&i.gid===24021&&Array.isArray(i.groups)&&i.groups.every(g=>g===24021)&&i.noNewPrivs===true&&
  i.effectiveCapabilities==='0'&&i.dockerSocketReadable===false&&i.kubeconfigReadable===false&&i.environmentInherited===false);
 check(Array.isArray(packet.router)&&packet.router.length===3);
 const router=packet.router.map(({receiptDigest,...body})=>{
  check(digest(body)===receiptDigest&&body.runId===runId&&body.resultDigests.gitleaks===r.resultDigest&&body.productionDelivery===false);
  return {consumerId:body.consumerId,deliveryDecision:body.deliveryDecision,resultDigest:r.resultDigest};
 });
 check(router.some(x=>x.consumerId==='local-evidence'&&x.deliveryDecision==='DELIVERED_LOCAL_ONLY'));
 const entries=Object.entries(packet.files??{});check(entries.length>4&&entries.length<=24);
 const files=Object.fromEntries(entries.map(([name,data])=>{
  check(/^[-a-zA-Z0-9_.]+\.json$/.test(name)&&name!=='security-summary.json'&&name.length<100);
  return [name,decode(data)];
 }));
 check(Object.values(files).reduce((n,b)=>n+b.length,0)<=256*1024);
 const parse=name=>JSON.parse(files[name]);
 const seal=parse('candidate-seal.json');
 check(digest(seal)===packet.artifactDigest&&Object.keys(seal.files).length===entries.length-1&&
  Object.keys(seal.files).every(n=>Object.hasOwn(files,n)&&n!=='candidate-seal.json'));
 const summary=parse('candidate-summary.json'),raw=parse('gitleaks.raw.json');
 check(summary.runId===runId&&summary.productionEvidence===false&&summary.promotion.status==='BLOCKED'&&
  summary.pluginResults.every(p=>p.pluginId==='gitleaks'?p.resultDigest===r.resultDigest:p.executionStatus==='DISABLED'));
 check(Array.isArray(raw)&&raw.length===f.findingsCount&&(commit?raw.every(x=>x.Secret==='[REDACTED]'&&!Object.hasOwn(x,'Match')&&x.File.startsWith(f.sourceDir.path+'/')):finding?raw.length>0&&raw.every(x=>x.RuleID==='github-pat'&&
  x.File===workspace+'/source-java/Main.java'&&x.StartLine===2&&/^\[?REDACTED\]?$/.test(x.Secret)):raw.length===0)&&
  sha(files['gitleaks.raw.json'])===r.rawReportDigest&&
  digest(parse('gitleaks.facts.json'))===r.factDigest&&digest(parse('gitleaks.runtime-facts.json'))===digest(f)&&
  digest(parse('gitleaks.result.json'))===digest(r));
 const staging=path.join(dir,'artifact.pending');fs.mkdirSync(staging,{mode:0o700});
 try{
  for(const [name,bytes] of Object.entries(files)){
   const fd=fs.openSync(path.join(staging,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
   try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  }
  verifyArtifact(staging,packet.artifactDigest);
  fs.renameSync(staging,path.join(dir,'artifact'));
 }finally{if(fs.existsSync(staging))fs.rmSync(staging,{recursive:true});}
 return {state:r.executionStatus,evidenceClass:'REAL',managerExecutionStatus:r.executionStatus,reason:null,scannerExecuted:true,
  scannerExitCode:f.command.exitStatus,toolVersion:f.tool.observedVersion,toolSha256:f.tool.sha256,executionHost:linuxHost,...(commit?{sourceMode:'REAL_COMMIT_SNAPSHOT',sourceCommitSha:f.sourceSnapshot.commitSha,sourceSnapshotSha256:f.sourceSnapshot.archiveSha256,sourceTreeOid:f.sourceSnapshot.rootTreeOid,sourceFileCount:f.sourceSnapshot.fileCount,sourceCleanup:'VERIFIED'}:{}),
  findingsCount:f.findingsCount,findingRules:[...new Set(raw.map(x=>x.RuleID))],
  executionIdentity:cleanIdentity,securityLevel:r.securityLevel,effectivePolicy:r.policy.effectivePolicy,appliedOverrides:r.policy.appliedOverrides,policyDecision:r.policyDecision,evaluationCount:r.evaluationCount,resultDigest:r.resultDigest,
  artifactDigest:packet.artifactDigest,rawReportDigest:r.rawReportDigest,factDigest:r.factDigest,router,
  scannerStartedAt:f.startedAt,scannerCompletedAt:f.completedAt,cleanup:r.cleanup.status};
}
