// Verify-only, offline, fixed Cosign native runner. Never reads a private key.
import fs from 'node:fs';import path from 'node:path';import {spawn} from 'node:child_process';import crypto from 'node:crypto';
import {sha,digest,freeze,fail} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {COSIGN_BLOB_MODE,blobArgv,legacyBlobDecision,cosignBlobSourceIdentity} from '../policy/cosign-blob-evidence.mjs';
let commands=0,verifications=0;export const cosignExecutionCounts=()=>({commands,verifications});
function trusted(p,dir=false){const s=fs.lstatSync(p);if(fs.realpathSync(p)!==p||s.uid!==0||(s.mode&0o022)||(dir?!s.isDirectory():!s.isFile())||!dir&&s.nlink!==1)fail('Cosign trusted file identity');return s;}
function hashFile(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),h=crypto.createHash('sha256'),b=Buffer.alloc(1024*1024);try{let n;while((n=fs.readSync(fd,b,0,b.length,null)))h.update(b.subarray(0,n));return h.digest('hex');}finally{fs.closeSync(fd);}}
function validate(input,projectId){
 keys(input,['approvalFile','objectId']);
 if(process.platform!=='linux'||process.arch!=='arm64'||process.getuid()===0||process.getgroups().some(g=>g===0||g===988))throw Error('COSIGN_UNSUPPORTED_IDENTITY');
 const s=fs.readFileSync('/proc/self/status','utf8');if(!/^NoNewPrivs:\s+1$/m.test(s)||!/^CapEff:\s+0+$/m.test(s))throw Error('COSIGN_UNSUPPORTED_IDENTITY');
 for(const p of ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml','/var/run/secrets/kubernetes.io/serviceaccount/token']){let access=false;try{fs.accessSync(p,fs.constants.R_OK);access=true;}catch{}if(access)fail('Cosign production authority accessible');}
 if(typeof input.approvalFile!=='string'||!/^\/var\/tmp\/security-manager-gitleaks-[a-zA-Z0-9_-]+\/cosign-approval\.json$/.test(input.approvalFile))fail('Cosign approval path');
 if(trusted(input.approvalFile).size>65536)fail('Cosign approval size');const a=JSON.parse(fs.readFileSync(input.approvalFile)),root=path.dirname(input.approvalFile);trusted(root,true);
 if(a.schemaVersion!==1||a.scope!=='SYNTHETIC_NON_RELEASE_OFFLINE_COSIGN_VERIFICATION'||a.workspace!==root||a.executionUid!==process.getuid()||!Array.isArray(a.objects)||!Array.isArray(a.trustIdentities)||a.authorization?.status!=='APPROVED_CONTROLLED_NON_PRODUCTION_FIXTURES_ONLY')fail('Cosign approval scope');
 const output=fs.lstatSync(a.outputRoot);if(!output.isDirectory()||fs.realpathSync(a.outputRoot)!==a.outputRoot||a.outputRoot!==root+'/outputs'||output.uid!==process.getuid()||(output.mode&0o077))fail('Cosign private output');
 const item=a.objects.find(x=>x.objectId===input.objectId&&x.projectId===projectId),trust=a.trustIdentities.find(x=>x.projectId===projectId);
 if(!item||!trust||item.trustId!==trust.trustId||trust.scope!=='CONTROLLED_TEST_ONLY_NOT_PRODUCTION')fail('Cosign unapproved object/project/trust');
 const objects=root+'/cosign-fixtures';trusted(objects,true);
 const check=(p,expected,limit)=>{if(typeof p!=='string'||!p.startsWith(objects+'/')||p.includes('..')||trusted(p).size>limit||hashFile(p)!==expected)fail('Cosign fixture identity');};
 check(item.objectPath,item.objectSha256,65536);check(trust.publicKeyPath,trust.publicKeySha256,8192);
 if(item.signaturePresent===true)check(item.signaturePath,item.signatureSha256,65536);
 else if(item.signaturePresent!==false||item.signatureSha256!==null||fs.existsSync(item.signaturePath))fail('Cosign missing-signature fact');
 // Reject arbitrary issuer/embedded-key trust: the only key comes from approved
 // project-scoped public key metadata, not from the object or signature.
 if(trust.publicKeySha256===sha(fs.readFileSync(new URL('../cosign.pub',import.meta.url))))fail('Production trust key prohibited for controlled objects');
 const source=cosignBlobSourceIdentity(),lock=JSON.parse(fs.readFileSync(new URL('../scanner-tools.json',import.meta.url))),tool=lock.files.find(x=>x.path==='cosign');
 if(a.tool.path===root+'/cosign'&&!fs.existsSync(a.tool.path))throw Error('COSIGN_TOOL_NOT_CONFIGURED');
 if(a.tool.path!==root+'/cosign'||a.tool.version!==lock.versions.cosign||trusted(a.tool.path).size!==tool.bytes||hashFile(a.tool.path)!==tool.sha256)fail('Cosign fixed tool identity');
 if(typeof item.sourceRevisionDigest!=='string'||!/^[a-f0-9]{64}$/.test(item.sourceRevisionDigest))fail('Cosign source binding');
 return {a,root,item,trust,source,toolSha256:tool.sha256,approvalSha256:hashFile(input.approvalFile),identity:{uid:process.getuid(),gid:process.getgid(),groups:process.getgroups(),noNewPrivs:true,capEff:'0',environmentInherited:false,privateKeyAccessibleToRunner:false,dockerReadable:false,kubeconfigReadable:false}};
}
async function command(bin,argv,cwd,timeout,signal,verification=false){
 if(signal?.aborted)throw Error('RUNNER_CANCELLED');if(timeout<=0)throw Error('RUNNER_TIMEOUT');
 const env={PATH:'/usr/bin:/bin',HOME:cwd,TMPDIR:cwd,LANG:'C',GOMAXPROCS:'1',GOMEMLIMIT:'128MiB',COSIGN_EXPERIMENTAL:'0'};
 const p=spawn(bin,argv,{cwd,env,detached:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='',cause,timer,killer;
 const kill=s=>{if(p.pid)try{process.kill(-p.pid,s);}catch(e){if(e.code!=='ESRCH')throw e;}};
 const stop=r=>{if(cause)return;cause=r;kill('SIGTERM');killer=setTimeout(()=>kill('SIGKILL'),100);};const abort=()=>stop('RUNNER_CANCELLED');signal?.addEventListener('abort',abort,{once:true});
 try{
  const result=await new Promise((resolve,reject)=>{
   p.once('spawn',()=>{commands++;if(verification)verifications++;});p.once('error',()=>reject(Error('RUNNER_ERROR')));
   p.stdout.on('data',b=>{stdout+=b;if(Buffer.byteLength(stdout)>65536)stop('RUNNER_OUTPUT_LIMIT');});p.stderr.on('data',b=>{stderr+=b;if(Buffer.byteLength(stderr)>65536)stop('RUNNER_OUTPUT_LIMIT');});
   p.once('close',(code,sig)=>resolve({exitStatus:code,signal:sig}));timer=setTimeout(()=>stop('RUNNER_TIMEOUT'),timeout);if(signal?.aborted)abort();
  });if(cause)throw Error(cause);return {...result,argv,stdout,stderr};
 }finally{clearTimeout(timer);clearTimeout(killer);signal?.removeEventListener('abort',abort);kill('SIGKILL');if(p.pid)try{process.kill(-p.pid,0);throw Error('RUNNER_CLEANUP_FAILED');}catch(e){if(e.code!=='ESRCH')throw e;}}
}
export async function executeRealCosign(plugin,input,{projectId,runId,signal}={}){
 const v=validate(input,projectId),dir=fs.mkdtempSync(path.join(v.a.outputRoot,'cosign-verify-')),startedAt=new Date().toISOString(),deadline=Date.now()+plugin.timeout;let observed=null;
 try{
  const version=await command(v.a.tool.path,['version','--json'],dir,Math.min(5000,deadline-Date.now()),signal);
  let versionJSON;try{versionJSON=JSON.parse(version.stdout);}catch{throw Error('RUNNER_TOOL_VERSION_ERROR');}
  if(version.exitStatus!==0||String(versionJSON.gitVersion??versionJSON.GitVersion).replace(/^v/,'')!==v.a.tool.version)throw Error('RUNNER_TOOL_VERSION_ERROR');
  const refs={key:v.trust.publicKeyPath,object:v.item.objectPath,signature:v.item.signaturePath,signaturePresent:v.item.signaturePresent};
  observed=await command(v.a.tool.path,blobArgv(refs),dir,deadline-Date.now(),signal,true);
  if(!Number.isInteger(observed.exitStatus)||observed.signal)throw Error('RUNNER_ERROR');
  const raw={schemaVersion:1,stage:COSIGN_BLOB_MODE,complete:true,classification:'REAL_CONTROLLED_OFFLINE_SIGNATURE_VERIFICATION',validationRunId:runId,
   binding:{projectId,objectId:v.item.objectId,objectSha256:v.item.objectSha256,signatureSha256:v.item.signatureSha256,sourceRevisionDigest:v.item.sourceRevisionDigest,approvalSha256:v.approvalSha256},
   trust:{trustId:v.trust.trustId,authorizedProject:projectId,publicKeySha256:v.trust.publicKeySha256,scope:v.trust.scope},refs,tool:{version:v.a.tool.version,sha256:v.toolSha256,platform:'linux/arm64'},command:observed};
  const old=legacyBlobDecision(raw);validate(input,projectId);
  const text=JSON.stringify(raw),fact={component:'cosign',status:'success',raw},runtimeFacts={schemaVersion:1,kind:'CandidateRuntimeSourceFacts',classification:'REAL_CONTROLLED_EXECUTION',pluginId:'cosign',validationRunId:runId,projectId,startedAt,completedAt:new Date().toISOString(),tool:raw.tool,toolVersionObservation:version,identity:v.identity,object:raw.binding,trust:raw.trust,command:observed,sourceIdentity:{manifestSha256:v.source.manifestSha256,checkerSha256:v.source.checkerSha256},oldGate:{decision:old.decision,scope:old.scope},rawReportDigest:sha(text),factDigest:digest(fact)};
  return freeze({rawReport:raw,rawReportBytesUtf8:text,rawReportDigest:sha(text),fact,factDigest:digest(fact),oldDecision:old.decision,runtimeFacts,evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',validationRunId:runId,objectSha256:v.item.objectSha256,trustKeySha256:v.trust.publicKeySha256,toolSha256:v.toolSha256,rawReportDigest:sha(text),canonicalRuntime:false}],executionScope:'REAL_CONTROLLED_OFFLINE_BLOB_VERIFICATION_NOT_PRODUCTION_TRUST',cleanup:{status:'VERIFIED',processGroupGone:true,privateReportDirectoryRemoved:true}});
 }catch(e){e.candidateEvidence={classification:'REAL_CONTROLLED_EXECUTION_ERROR',startedAt,completedAt:new Date().toISOString(),verificationObservation:observed,rawReportBytesUtf8:observed?JSON.stringify(observed):null,rawReportDigest:observed?sha(JSON.stringify(observed)):null};throw e;}
 finally{fs.rmSync(dir,{recursive:true});if(fs.existsSync(dir))throw Error('RUNNER_CLEANUP_FAILED');}
}
