// Dedicated SSH transport only. Semgrep scanning/normalization/Policy remain in existing Candidate modules.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {verifyArtifact,verifyResult} from '../result.mjs';
import {digest,sha} from '../../summary-v2/codec.mjs';
const exec=promisify(execFile),key=path.join(os.homedir(),'.ssh/security-manager-v2-semgrep'),known=path.join(os.homedir(),'.ssh/known_hosts');
const optIn=new URL('../../../../.devsecops/security-view-semgrep-linux-v1.json',import.meta.url);
const workspace='/var/tmp/security-manager-gitleaks-semgrep-web-20261106';
const binarySha='886b69c889897ea13e23aba5f541c59ee1356c55218ebc21e07b7ab45f1256d2';
export const semgrepHost='devops/192.168.64.11',semgrepIdentity='security-semgrep (UID 995 / GID 986)';
const fault=code=>Object.assign(Error(code),{code});
const check=ok=>{if(!ok)throw fault('LINUX_SEMGREP_EVIDENCE_REJECTED');};
function owned(p,mask,max){const s=fs.lstatSync(p);return s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&!(s.mode&mask)&&s.size>0&&s.size<=max;}
export function semgrepReady(){try{return owned(optIn,0o077,128)&&owned(key,0o077,8192)&&owned(known,0o022,1048576)&&fs.readFileSync(optIn,'utf8').trim()==='{"enabled":true}';}catch{return false;}}
const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
 '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
 '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+known,'-o','GlobalKnownHostsFile=/dev/null',
 '-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
 '-o','ServerAliveInterval=4','-o','ServerAliveCountMax=2','security-semgrep@192.168.64.11'];
export async function runLinuxSemgrep(scenarioId,runId,dir,signal,securityLevel='standard'){
 if(!['low','standard','strict'].includes(securityLevel))throw fault('INVALID_CANDIDATE_SECURITY_LEVEL');
 if(!semgrepReady())throw fault('LINUX_SEMGREP_NOT_CONFIGURED_BLOCKED');
 check(['clean','controlled-finding'].includes(scenarioId)&&/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(runId));
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',[...args,(scenarioId==='clean'?'clean-v1 ':'finding-v1 ')+runId+' '+securityLevel],{signal,timeout:29000,maxBuffer:524288,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}
 catch(e){let code;try{code=JSON.parse(e.stdout).error;}catch{}
  throw fault(['LINUX_RESOURCE_BUDGET_BLOCKED','RESOURCE_STATE_UNKNOWN_BLOCKED','EXECUTION_BUSY','OUTPUT_BUDGET_EXHAUSTED','EXECUTION_TIMEOUT','EXECUTION_OR_OUTPUT_REJECTED','DESCENDANT_CLEANUP_FAILED','PRODUCTION_AUTHORITY_READABLE'].includes(code)?code:'LINUX_SEMGREP_TRANSPORT_ERROR');}
 return acceptLinuxSemgrepPacket(packet,scenarioId,runId,dir,securityLevel);
}
export function acceptLinuxSemgrepPacket(packet,scenarioId,runId,dir,securityLevel='standard'){
 check(['clean','controlled-finding'].includes(scenarioId)&&packet?.schemaVersion===1&&packet.kind==='RestrictedLinuxSemgrep'&&packet.runId===runId&&packet.scenarioId===scenarioId&&packet.executionHost===semgrepHost);
 const r=packet.result,f=r?.runtimeFacts,i=f?.identity;verifyResult(r);check(['low','standard','strict'].includes(securityLevel)&&r.securityLevel===securityLevel&&r.policy?.securityLevel===securityLevel&&r.policy?.evaluation?.securityLevel===securityLevel);
 check(r.runId===runId&&r.pluginId==='semgrep'&&r.projectId==='java-fixture'&&r.executionStatus==='COMPLETED'&&r.evaluationCount===1&&packet.policyEvaluationCount===1&&packet.executionCounts?.scans===1&&r.policyDecision===r.oldGateDecision&&r.policyDecision===(scenarioId==='clean'?'PASS':'FAIL'));
 check(f.classification==='REAL_CONTROLLED_EXECUTION'&&f.validationRunId===runId&&f.sourceDir.path===workspace+'/source-'+scenarioId&&f.tool.sha256===binarySha&&f.tool.version==='1.182.1'&&f.tool.observedVersion==='semgrep-core version: 1.182.1 (6f7d77ede0)'&&f.filesScanned===1&&f.commands.length===2&&f.commands.every(c=>c.exitStatus===0&&c.signal===null)&&r.cleanup?.processGroupGone===true);
 check(i.uid===995&&i.gid===986&&Array.isArray(i.groups)&&i.groups.every(g=>g===986)&&i.noNewPrivs===true&&i.capEff==='0'&&i.dockerReadable===false&&i.kubeconfigReadable===false&&i.environmentInherited===false);
 check(Array.isArray(packet.router)&&packet.router.length===3);
 const router=packet.router.map(({receiptDigest,...body})=>{check(digest(body)===receiptDigest&&body.runId===runId&&body.resultDigests.semgrep===r.resultDigest&&body.productionDelivery===false);return {consumerId:body.consumerId,deliveryDecision:body.deliveryDecision,resultDigest:r.resultDigest};});
 check(router.some(c=>c.consumerId==='local-evidence'&&c.deliveryDecision==='DELIVERED_LOCAL_ONLY'));
 const entries=Object.entries(packet.files??{});check(entries.length>4&&entries.length<=24);
 const files=Object.fromEntries(entries.map(([name,data])=>{check(/^[-a-zA-Z0-9_.]+\.json$/.test(name)&&name!=='security-summary.json'&&name.length<100&&typeof data==='string'&&data.length<=175000&&/^[A-Za-z0-9+/]+={0,2}$/.test(data));const bytes=Buffer.from(data,'base64');check(bytes.toString('base64')===data&&bytes.length<=128*1024);return [name,bytes];}));
 check(Object.values(files).reduce((n,b)=>n+b.length,0)<=256*1024);
 const parse=n=>JSON.parse(files[n]);const seal=parse('candidate-seal.json'),summary=parse('candidate-summary.json'),raw=parse('semgrep.raw.json');
 check(digest(seal)===packet.artifactDigest&&Object.keys(seal.files).length===entries.length-1&&Object.keys(seal.files).every(n=>Object.hasOwn(files,n)&&n!=='candidate-seal.json'));
 check(summary.runId===runId&&summary.productionEvidence===false&&summary.promotion.status==='BLOCKED'&&summary.pluginResults.every(p=>p.pluginId==='semgrep'?p.resultDigest===r.resultDigest:p.executionStatus==='DISABLED'));
 check(raw.kind==='SemgrepNativeReportCollection'&&raw.reports.length===1&&raw.nativeReportTexts.length===1&&raw.nativeReportTexts.every((x,n)=>sha(x.bytesUtf8)===x.sha256&&digest(JSON.parse(x.bytesUtf8))===digest(raw.reports[n])));
 const findings=raw.reports.flatMap(x=>{check(Array.isArray(x.results)&&Array.isArray(x.errors)&&x.errors.length===0);return x.results;});
 check(findings.length===f.findingsCount&&(scenarioId==='clean'?findings.length===0:findings.length>0)&&findings.every(x=>x.path===workspace+'/source-'+scenarioId+'/Main.java'&&f.rules.ruleIds.includes(x.check_id??x.rule_id))&&sha(files['semgrep.raw.json'])===r.rawReportDigest&&digest(parse('semgrep.facts.json'))===r.factDigest&&digest(parse('semgrep.runtime-facts.json'))===digest(f)&&digest(parse('semgrep.result.json'))===digest(r));
 const staging=path.join(dir,'artifact.pending');fs.mkdirSync(staging,{mode:0o700});
 try{for(const [name,bytes]of Object.entries(files)){const fd=fs.openSync(path.join(staging,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
  verifyArtifact(staging,packet.artifactDigest);fs.renameSync(staging,path.join(dir,'artifact'));
 }finally{if(fs.existsSync(staging))fs.rmSync(staging,{recursive:true});}
 return {state:'COMPLETED',evidenceClass:'REAL',managerExecutionStatus:r.executionStatus,reason:null,scannerExecuted:true,scannerExitCode:f.commands.at(-1).exitStatus,
 toolVersion:f.tool.observedVersion,toolSha256:f.tool.sha256,executionHost:semgrepHost,executionIdentity:semgrepIdentity,findingsCount:f.findingsCount,
 findingRules:[...new Set(findings.map(x=>x.check_id??x.rule_id))],securityLevel:r.securityLevel,effectivePolicy:r.policy.effectivePolicy,appliedOverrides:r.policy.appliedOverrides,policyDecision:r.policyDecision,evaluationCount:r.evaluationCount,resultDigest:r.resultDigest,
 artifactDigest:packet.artifactDigest,rawReportDigest:r.rawReportDigest,factDigest:r.factDigest,router,scannerStartedAt:f.startedAt,scannerCompletedAt:f.completedAt,cleanup:r.cleanup.status};
}
