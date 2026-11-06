// Dedicated verify-only SSH transport. Existing Cosign Runner/Policy perform the work; no signing key access.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {verifyArtifact,verifyResult} from '../result.mjs';
import {digest,sha} from '../../summary-v2/codec.mjs';
const exec=promisify(execFile),key=path.join(os.homedir(),'.ssh/security-manager-v2-cosign'),known=path.join(os.homedir(),'.ssh/known_hosts');
const optIn=new URL('../../../../.devsecops/security-view-cosign-linux-v1.json',import.meta.url);
const workspace='/var/tmp/security-manager-gitleaks-cosign-web-20261106';
const binarySha='ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2';
export const cosignHost='devops/192.168.64.11',cosignIdentity='security-cosign (UID 994 / GID 985)';
const fault=code=>Object.assign(Error(code),{code});
const check=ok=>{if(!ok)throw fault('LINUX_COSIGN_EVIDENCE_REJECTED');};
function owned(p,mask,max){const s=fs.lstatSync(p);return s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&!(s.mode&mask)&&s.size>0&&s.size<=max;}
export function cosignReady(){try{return owned(optIn,0o077,128)&&owned(key,0o077,8192)&&owned(known,0o022,1048576)&&fs.readFileSync(optIn,'utf8').trim()==='{"enabled":true}';}catch{return false;}}
const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
 '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
 '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+known,'-o','GlobalKnownHostsFile=/dev/null',
 '-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
 '-o','ServerAliveInterval=4','-o','ServerAliveCountMax=2','security-cosign@192.168.64.11'];
export async function runLinuxCosign(scenarioId,runId,dir,signal){
 if(!cosignReady())throw fault('LINUX_COSIGN_NOT_CONFIGURED_BLOCKED');
 check(['clean','controlled-finding'].includes(scenarioId)&&/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(runId));
 let packet;try{const {stdout}=await exec('/usr/bin/ssh',[...args,(scenarioId==='clean'?'valid-v1 ':'invalid-v1 ')+runId],{signal,timeout:29000,maxBuffer:524288,env:{PATH:'/usr/bin:/bin',LANG:'C'}});packet=JSON.parse(stdout);}
 catch(e){let code;try{code=JSON.parse(e.stdout).error;}catch{}
  throw fault(['LINUX_RESOURCE_BUDGET_BLOCKED','RESOURCE_STATE_UNKNOWN_BLOCKED','EXECUTION_BUSY','OUTPUT_BUDGET_EXHAUSTED','EXECUTION_TIMEOUT','EXECUTION_OR_OUTPUT_REJECTED','DESCENDANT_CLEANUP_FAILED','PRODUCTION_AUTHORITY_READABLE'].includes(code)?code:'LINUX_COSIGN_TRANSPORT_ERROR');}
 return acceptLinuxCosignPacket(packet,scenarioId,runId,dir);
}
export function acceptLinuxCosignPacket(packet,scenarioId,runId,dir){
 check(['clean','controlled-finding'].includes(scenarioId)&&packet?.schemaVersion===1&&packet.kind==='RestrictedLinuxCosign'&&packet.runId===runId&&packet.scenarioId===scenarioId&&packet.executionHost===cosignHost);
 const r=packet.result,f=r?.runtimeFacts,i=f?.identity;verifyResult(r);
 check(r.runId===runId&&r.pluginId==='cosign'&&r.projectId==='java-fixture'&&r.executionStatus==='COMPLETED'&&r.evaluationCount===1&&packet.policyEvaluationCount===1&&packet.executionCounts?.verifications===1&&packet.executionCounts?.commands===2&&r.policyDecision===r.oldGateDecision&&r.policyDecision===(scenarioId==='clean'?'PASS':'FAIL'));
 const invalid=scenarioId==='controlled-finding',objectName='java-fixture-'+(invalid?'tampered':'valid');
 const objectSha=invalid?'90564abcbe4aa3395e7ceb7ab598778b1e64a299d285a7097afe94e0e2e2f480':'d6d0bbaaef787bd7de7d776ca408060d4745b01e6136843505558caf6231aaca';
 check(f.classification==='REAL_CONTROLLED_EXECUTION'&&f.validationRunId===runId&&f.tool.sha256===binarySha&&f.tool.version==='3.1.4'&&f.tool.platform==='linux/arm64'&&f.command.exitStatus===(invalid?1:0)&&f.command.signal===null&&r.cleanup?.processGroupGone===true);
 check(f.object.objectId===objectName&&f.object.objectSha256===objectSha&&f.object.sourceRevisionDigest==='d6d0bbaaef787bd7de7d776ca408060d4745b01e6136843505558caf6231aaca'&&f.object.signatureSha256==='2050c91b38871262920bcc8a4efe9025aaf43500efc8d90860d4efb3c81aa44b');
 check(f.trust.trustId==='java-fixture-test-key'&&f.trust.authorizedProject==='java-fixture'&&f.trust.scope==='CONTROLLED_TEST_ONLY_NOT_PRODUCTION'&&f.trust.publicKeySha256==='053e9751b649590ba28ac9e57eb3f4b09304eefa0987db939a1598225d6c923d');
 check(f.toolVersionObservation.exitStatus===0&&f.toolVersionObservation.signal===null&&JSON.parse(f.toolVersionObservation.stdout).gitVersion==='v3.1.4');
 check(i.uid===994&&i.gid===985&&Array.isArray(i.groups)&&i.groups.every(g=>g===985)&&i.noNewPrivs===true&&i.capEff==='0'&&i.dockerReadable===false&&i.kubeconfigReadable===false&&i.environmentInherited===false&&i.privateKeyAccessibleToRunner===false);
 check(Array.isArray(packet.router)&&packet.router.length===3);
 const router=packet.router.map(({receiptDigest,...body})=>{check(digest(body)===receiptDigest&&body.runId===runId&&body.resultDigests.cosign===r.resultDigest&&body.productionDelivery===false);return {consumerId:body.consumerId,deliveryDecision:body.deliveryDecision,resultDigest:r.resultDigest};});
 check(router.some(c=>c.consumerId==='local-evidence'&&c.deliveryDecision==='DELIVERED_LOCAL_ONLY'));
 const entries=Object.entries(packet.files??{});check(entries.length>4&&entries.length<=24);
 const files=Object.fromEntries(entries.map(([name,data])=>{check(/^[-a-zA-Z0-9_.]+\.json$/.test(name)&&name!=='security-summary.json'&&name.length<100&&typeof data==='string'&&data.length<=175000&&/^[A-Za-z0-9+/]+={0,2}$/.test(data));const bytes=Buffer.from(data,'base64');check(bytes.toString('base64')===data&&bytes.length<=128*1024);return [name,bytes];}));
 check(Object.values(files).reduce((n,b)=>n+b.length,0)<=256*1024);
 const parse=n=>JSON.parse(files[n]);const seal=parse('candidate-seal.json'),summary=parse('candidate-summary.json'),raw=parse('cosign.raw.json');
 check(digest(seal)===packet.artifactDigest&&Object.keys(seal.files).length===entries.length-1&&Object.keys(seal.files).every(n=>Object.hasOwn(files,n)&&n!=='candidate-seal.json'));
 check(summary.runId===runId&&summary.productionEvidence===false&&summary.promotion.status==='BLOCKED'&&summary.pluginResults.every(p=>p.pluginId==='cosign'?p.resultDigest===r.resultDigest:p.executionStatus==='DISABLED'));
 check(raw.schemaVersion===1&&raw.complete===true&&raw.stage==='candidate-offline-blob-v1'&&raw.classification==='REAL_CONTROLLED_OFFLINE_SIGNATURE_VERIFICATION'&&raw.validationRunId===runId&&digest(raw.binding)===digest(f.object)&&digest(raw.trust)===digest(f.trust)&&digest(raw.command)===digest(f.command)&&digest(raw.tool)===digest(f.tool));
 check(raw.refs.key===workspace+'/cosign-fixtures/java-fixture.pub'&&raw.refs.signature===workspace+'/cosign-fixtures/java-fixture-valid.sig'&&raw.refs.object===workspace+'/cosign-fixtures/'+objectName+'.json'&&raw.refs.signaturePresent===true);
 check(digest(raw.command.argv)===digest(['verify-blob','--key',raw.refs.key,'--insecure-ignore-tlog=true','--signature',raw.refs.signature,raw.refs.object]));
 check(typeof raw.command.stderr==='string'&&(invalid?raw.command.stderr.length>0&&!raw.command.stderr.includes('Verified OK'):raw.command.stderr.includes('Verified OK')));
 check(sha(files['cosign.raw.json'])===r.rawReportDigest&&digest(parse('cosign.facts.json'))===r.factDigest&&digest(parse('cosign.facts.json').raw)===digest(raw)&&digest(parse('cosign.runtime-facts.json'))===digest(f)&&digest(parse('cosign.result.json'))===digest(r));
 const staging=path.join(dir,'artifact.pending');fs.mkdirSync(staging,{mode:0o700});
 try{for(const [name,bytes]of Object.entries(files)){const fd=fs.openSync(path.join(staging,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
  verifyArtifact(staging,packet.artifactDigest);fs.renameSync(staging,path.join(dir,'artifact'));
 }finally{if(fs.existsSync(staging))fs.rmSync(staging,{recursive:true});}
 return {state:'COMPLETED',evidenceClass:'REAL',managerExecutionStatus:r.executionStatus,reason:null,scannerExecuted:true,scannerExitCode:f.command.exitStatus,
 toolVersion:JSON.parse(f.toolVersionObservation.stdout).gitVersion,toolSha256:f.tool.sha256,executionHost:cosignHost,executionIdentity:cosignIdentity,
 verificationStatus:invalid?'REJECTED':'VERIFIED',verificationReason:raw.command.stderr.slice(-800),verifiedObjectDigest:'sha256:'+objectSha,trustPublicKeyDigest:'sha256:'+f.trust.publicKeySha256,
 policyDecision:r.policyDecision,evaluationCount:r.evaluationCount,resultDigest:r.resultDigest,artifactDigest:packet.artifactDigest,rawReportDigest:r.rawReportDigest,factDigest:r.factDigest,router,
 scannerStartedAt:f.startedAt,scannerCompletedAt:f.completedAt,cleanup:r.cleanup.status};
}
