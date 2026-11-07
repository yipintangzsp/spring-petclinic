// Trusted directory-scan adapter only. No Docker/Kubernetes/network/shell client.
import fs from 'node:fs';import path from 'node:path';import {spawn} from 'node:child_process';import vm from 'node:vm';import crypto from 'node:crypto';
import {sha,digest,freeze,fail} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';import {verifyGitleaksSourceLock} from '../policy/gitleaks-source-lock.mjs';
import {verifySourceTree} from './ci/source-tree.mjs';
let scans=0,commands=0;export const realExecutionCounts=()=>({scans,commands});
function trustedFile(p){const real=fs.realpathSync(p),s=fs.lstatSync(p);if(real!==p||!s.isFile()||s.uid!==0||(s.mode&0o022))fail('untrusted validation file');return s;}
function validate(input,projectId){
 keys(input,['approvalFile','sourceDir']);
 if(process.platform!=='linux'||process.getuid()===0||process.getgroups().some(g=>g===0||g===988))throw Error('GITLEAKS_UNSUPPORTED_IDENTITY');
 const identity=fs.readFileSync('/proc/self/status','utf8');if(!/^NoNewPrivs:\s+1$/m.test(identity)||!/^CapEff:\s+0+$/m.test(identity))throw Error('GITLEAKS_UNSUPPORTED_IDENTITY');
 for(const p of ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml']){let readable=false;try{fs.accessSync(p,fs.constants.R_OK);readable=true;}catch{}if(readable)fail('production authority accessible');}
 if(typeof input.approvalFile!=='string'||!/^\/var\/tmp\/security-manager-gitleaks-[a-zA-Z0-9_-]+\/approval\.json$/.test(input.approvalFile))fail('validation approval path');
 if(trustedFile(input.approvalFile).size>65536)fail('approval budget');const approval=JSON.parse(fs.readFileSync(input.approvalFile));
 const domain=path.dirname(input.approvalFile),d=fs.lstatSync(domain);if(d.uid!==0||(d.mode&0o022)||fs.realpathSync(domain)!==domain)fail('validation domain ownership');
 if(approval.schemaVersion!==1||!['SYNTHETIC_NON_RELEASE_DIR_SCAN','REAL_COMMIT_SNAPSHOT'].includes(approval.scope)||approval.workspace!==domain||approval.executionUid!==process.getuid())fail('approval scope/identity');
 const out=fs.lstatSync(approval.outputRoot);if(approval.outputRoot!==domain+'/outputs'||fs.realpathSync(approval.outputRoot)!==approval.outputRoot||out.uid!==process.getuid()||(out.mode&0o077))fail('private output ownership');
 const real=approval.scope==='REAL_COMMIT_SNAPSHOT';let source;
 if(real){
  if(projectId!==approval.projectId||!input.sourceDir.startsWith(approval.outputRoot+'/')||path.basename(input.sourceDir)!=='source')fail('real source project/path');
  const parent=path.dirname(input.sourceDir);if(path.dirname(parent)!==approval.outputRoot||!/^source-web-[a-f0-9-]{36}$/.test(path.basename(parent)))fail('real source run domain');
  const s=fs.lstatSync(parent);if(s.uid!==process.getuid()||(s.mode&0o077)||fs.realpathSync(parent)!==parent)fail('real source ownership');
  const proof=JSON.parse(fs.readFileSync(parent+'/source-proof.json'));
  if(proof.commitSha!==approval.commitSha||proof.rootTreeOid!==approval.rootTreeOid||proof.projectId!==projectId||proof.branch!==approval.branch||proof.repository!==approval.sourceRepository||!/^[a-f0-9]{64}$/.test(proof.archiveSha256))fail('real source approval binding');
  const identity=verifySourceTree(input.sourceDir,proof.gitEntries,approval.rootTreeOid,approval.limits,process.getuid());
  source={sourceDir:input.sourceDir,projectId,sourceRevision:proof.commitSha,inode:fs.statSync(input.sourceDir).ino,device:fs.statSync(input.sourceDir).dev,...identity,snapshot:{sourceMode:'REAL_COMMIT_SNAPSHOT',commitSha:proof.commitSha,rootTreeOid:proof.rootTreeOid,archiveSha256:proof.archiveSha256,repository:proof.repository,branch:proof.branch,...identity}};
 }else{
 source=approval.sources.find(s=>s.sourceDir===input.sourceDir&&s.projectId===projectId);if(!source||!source.sourceDir.startsWith(domain+'/source-')||!/^[a-f0-9]{40}$/.test(source.sourceRevision))fail('SOURCE_DIR not approved');
 const ds=fs.lstatSync(source.sourceDir);if(ds.uid!==0||ds.ino!==source.inode||ds.dev!==source.device||(ds.mode&0o022))fail('source identity');
 const seen=[];function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const full=path.join(dir,entry.name),rel=path.relative(source.sourceDir,full);if(rel.split('/').some(x=>x==='.git'||x.startsWith('.gitleaks')))fail('source config/history prohibited');if(entry.isDirectory())walk(full);else{if(!entry.isFile())fail('source symlink/type');const s=trustedFile(full);if(s.size>65536)fail('source size');seen.push({path:rel,sha256:sha(fs.readFileSync(full)),bytes:s.size});}if(seen.length>16)fail('source count');}}
 walk(source.sourceDir);seen.sort((a,b)=>a.path.localeCompare(b.path));if(digest(seen)!==source.fileManifestDigest)fail('source content identity');
 }
 const tool=approval.tool;if(tool.path!==(approval.scope==='REAL_COMMIT_SNAPSHOT'?'/var/tmp/security-manager-gitleaks-v2-linux-20261105/gitleaks':domain+'/gitleaks')||trustedFile(tool.path).size>100*1024*1024||sha(fs.readFileSync(tool.path))!==tool.sha256)fail('tool identity');
 const lock=JSON.parse(fs.readFileSync(new URL('../tools-lock.json',import.meta.url))).gitleaks;
 if(tool.version!==lock.version||tool.image!==lock.image)fail('tool version/image lineage');
 const sourceLock=verifyGitleaksSourceLock();
 return {approval,source,tool,sourceLock,identity:{uid:process.getuid(),gid:process.getgid(),groups:process.getgroups(),noNewPrivs:true,effectiveCapabilities:'0',dockerSocketReadable:false,kubeconfigReadable:false,environmentInherited:false}};
}
async function command(bin,args,cwd,timeout,signal){
 if(signal?.aborted)throw Error('RUNNER_CANCELLED');commands++;
 const p=spawn(bin,args,{cwd,env:{PATH:'/usr/bin:/bin',HOME:cwd,LANG:'C',GOMAXPROCS:'1',GOMEMLIMIT:'128MiB'},detached:true,stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='',timer,killer,cause=null;const kill=s=>{if(p.pid)try{process.kill(-p.pid,s);}catch(e){if(e.code!=='ESRCH')throw e;}};
 const stop=reason=>{cause=reason;kill('SIGTERM');killer=setTimeout(()=>kill('SIGKILL'),100);};const abort=()=>stop('RUNNER_CANCELLED');signal?.addEventListener('abort',abort,{once:true});
 try{
  const result=await new Promise((resolve,reject)=>{
   p.on('error',()=>reject(Error('RUNNER_ERROR')));p.stdout.on('data',b=>{stdout+=b;if(stdout.length>65536)stop('RUNNER_OUTPUT_LIMIT');});p.stderr.on('data',b=>{stderr+=b;if(stderr.length>65536)stop('RUNNER_OUTPUT_LIMIT');});
   p.once('close',(code,sig)=>resolve({code,signal:sig}));timer=setTimeout(()=>stop('RUNNER_TIMEOUT'),timeout);if(signal?.aborted)abort();
  });
  if(cause)throw Error(cause);return {...result,stdout,stderrSha256:sha(stderr),argv:args};
 }finally{
  clearTimeout(timer);clearTimeout(killer);signal?.removeEventListener('abort',abort);kill('SIGKILL');
  if(p.pid){try{process.kill(-p.pid,0);throw Error('RUNNER_CLEANUP_FAILED');}catch(e){if(e.code!=='ESRCH')throw e;}}
 }
}
// Run the exact original production classification block, not a rewritten rule.
// Only the source prefix is mapped bijectively to its original /work/source root.
function oldClassifier(findings,sourceDir,reviewed){
 const code=fs.readFileSync(new URL('../source-gate.mjs',import.meta.url),'utf8'),begin=code.indexOf(' const reviewed='),end=code.indexOf(' const peak=');
 if(begin<0||end<=begin)fail('original classifier boundary');
 const mapped=findings.map(f=>({...f,file:'/work/source/'+path.relative(sourceDir,f.file)})),report={sourceScan:{findings:mapped}};let decision='PASS';
 try{vm.runInNewContext(code.slice(begin,end),{fs:{readFileSync:()=>JSON.stringify({entries:reviewed})},report,crypto,exec:args=>{const rel=args[1].slice('/work/source/'.length);return {stdout:fs.readFileSync(path.join(sourceDir,rel),'utf8')};}},{timeout:1000});}catch(e){if(!/^Secret gate blocked \d+ unaccepted findings; review redacted locations$/.test(e.message))throw Error('ORIGINAL_GATE_CLASSIFIER_ERROR');decision='FAIL';}
 return {decision,codeSha256:sha(code.slice(begin,end)),scope:'ORIGINAL_SOURCE_SECRET_CLASSIFIER_ON_REAL_INPUT','prefixMapping':'bijective sourceDir -> /work/source; native raw report remains unchanged',blockingCount:report.sourceScan.blockingFindings?.length??0};
}
export async function executeRealGitleaks(plugin,input,{signal,projectId,runId}={}){
 const v=validate(input,projectId),privateDir=fs.mkdtempSync(path.join(v.approval.outputRoot,'scan-')),rawPath=path.join(privateDir,'native.json');let rawText,observed;
 try{
  const version=await command(v.tool.path,['version'],privateDir,Math.min(plugin.timeout,5000),signal);
  if(version.code!==0||version.stdout.trim().replace(/^v(?=\d)/,'')!==v.tool.version)throw Error('RUNNER_TOOL_VERSION_ERROR');
  const argv=['dir',v.source.sourceDir,'--redact=100','--no-banner','--log-level','error','--report-format','json','--report-path',rawPath];
  const startedAt=new Date().toISOString();scans++;observed=await command(v.tool.path,argv,privateDir,plugin.timeout,signal);const completedAt=new Date().toISOString();
  if(![0,1].includes(observed.code)||observed.signal)throw Error('RUNNER_SCANNER_ERROR');
  const s=fs.lstatSync(rawPath);if(!s.isFile()||s.isSymbolicLink()||s.size>1024*1024)throw Error('RUNNER_REPORT_ERROR');rawText=fs.readFileSync(rawPath,'utf8');const native=JSON.parse(rawText);if(!Array.isArray(native)||native.length>128)throw Error('RUNNER_REPORT_ERROR');
  const originalNativeDigest=sha(rawText);
  const findings=native.map(f=>{
   if(typeof f.File!=='string'||!f.File.startsWith(v.source.sourceDir+'/')||!Number.isSafeInteger(f.StartLine)||f.StartLine<1||typeof f.RuleID!=='string'||!/^(?:\[?REDACTED\]?|)$/.test(f.Secret??''))throw Error('RUNNER_UNSAFE_REPORT');
   return {rule:f.RuleID,file:f.File,line:f.StartLine,fingerprint:f.Fingerprint??''};
  });
  if(v.source.snapshot){rawText=JSON.stringify(native.map(f=>({RuleID:f.RuleID,File:f.File,StartLine:f.StartLine,Secret:'[REDACTED]',Fingerprint:sha(String(f.Fingerprint??''))})));}
  const reviewed=JSON.parse(fs.readFileSync(new URL('../reviewed-false-positives.json',import.meta.url))).entries;
  const sourceLines=findings.map(f=>{const relative=path.relative(v.source.sourceDir,f.file);if(relative.includes('..'))fail('finding path');const text=fs.readFileSync(f.file,'utf8').split(/\r?\n/)[f.line-1];if(text===undefined)fail('finding source line absent');return {path:relative,line:f.line,sha256:sha(text)};});
  const fact={component:'gitleaks',status:'success',raw:{sourcePrefix:v.source.sourceDir+'/',findings,reviewedEntries:reviewed,sourceLines}};
  const oldGate=oldClassifier(findings,v.source.sourceDir,reviewed);
  // Recheck approved content after the scan and original classifier observation.
  validate(input,projectId);
  const execution={schemaVersion:1,kind:'CandidateRuntimeSourceFacts',validationRunId:runId,projectId,classification:'REAL_CONTROLLED_EXECUTION',sourceRevision:v.source.sourceRevision,...(v.source.snapshot?{sourceSnapshot:v.source.snapshot,originalNativeReportSha256:originalNativeDigest}:{}),sourceDir:{path:v.source.sourceDir,inode:v.source.inode,device:v.source.device,fileManifestDigest:v.source.fileManifestDigest},tool:{version:v.tool.version,observedVersion:version.stdout.trim(),sha256:v.tool.sha256,image:v.tool.image},config:{kind:'EXISTING_BUILTIN_DEFAULT',digest:digest({version:v.tool.version,toolSha256:v.tool.sha256,mode:'dir',environmentConfigAbsent:true})},command:{executableSha256:v.tool.sha256,argv,exitStatus:observed.code,signal:observed.signal,stderrSha256:observed.stderrSha256},startedAt,completedAt,identity:v.identity,oldGate,sourceBaselineId:v.sourceLock.baselineId,rawReportDigest:sha(rawText),factDigest:digest(fact),findingsCount:findings.length};
  return freeze({rawReport:native,rawReportBytesUtf8:rawText,rawReportDigest:sha(rawText),fact,factDigest:digest(fact),oldDecision:oldGate.decision,runtimeFacts:execution,evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',validationRunId:runId,sourceRevision:v.source.sourceRevision,toolSha256:v.tool.sha256,rawReportDigest:sha(rawText),canonicalRuntime:false}],executionScope:v.source.snapshot?'REAL_COMMIT_SNAPSHOT':'REAL_CONTROLLED_NON_RELEASE_DIR_SCAN',cleanup:{status:'VERIFIED',processGroupGone:true,privateReportDirectoryRemoved:true,...(v.source.snapshot?{sourceWorkspaceRemoved:true}:{})}});
 }finally{if(v.source.snapshot){const sourceParent=path.dirname(input.sourceDir);fs.rmSync(sourceParent,{recursive:true});if(fs.existsSync(sourceParent))throw Error('RUNNER_CLEANUP_FAILED');}fs.rmSync(privateDir,{recursive:true});if(fs.existsSync(privateDir))throw Error('RUNNER_CLEANUP_FAILED');}
}
