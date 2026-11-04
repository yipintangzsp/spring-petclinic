// Fixed offline native-core adapter. Project source is passive input only.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {spawn} from 'node:child_process';
import {sha,digest,freeze,fail} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {classifySemgrep} from '../semgrep-policy.mjs';
let scans=0,commands=0,nativeCommands=0;
export const semgrepExecutionCounts=()=>({scans,commands,nativeCommands});
export function semgrepSourceIdentity(){
 const bytes=fs.readFileSync(new URL('../policy/versions/command-parent-baseline-v1.json',import.meta.url));
 if(sha(bytes)!=='f83a876ca96c5943b83bc289aeb27282fff7d9eb42cd2be0e1fdb6b41d098482')fail('Semgrep frozen manifest changed');
 const baseline=JSON.parse(bytes);
 for(const [p,h]of Object.entries(baseline.sourceHashes))if(sha(fs.readFileSync(new URL('../../../'+p,import.meta.url)))!==h)fail('Semgrep frozen source changed: '+p);
 return {baseline:'command-parent-baseline-v1',manifestSha256:sha(bytes),sourceHashes:baseline.sourceHashes};
}
function hashFile(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),h=crypto.createHash('sha256'),b=Buffer.alloc(1024*1024);try{let n;while((n=fs.readSync(fd,b,0,b.length,null)))h.update(b.subarray(0,n));return h.digest('hex');}finally{fs.closeSync(fd);}}
function trusted(p,directory=false){const s=fs.lstatSync(p);if(fs.realpathSync(p)!==p||s.uid!==0||(s.mode&0o022)||(directory?!s.isDirectory():!s.isFile())||!directory&&s.nlink!==1)fail('Semgrep untrusted file/type/owner');return s;}
export function normalizeSemgrepNative(reports,sourceDir,files,ruleIds){
 if(!Array.isArray(reports)||reports.length!==files.length||!files.length)throw Error('RUNNER_REPORT_ERROR');
 const findings=[];
 for(let i=0;i<reports.length;i++){
  const r=reports[i];if(!r||!Array.isArray(r.results)||!Array.isArray(r.errors))throw Error('RUNNER_REPORT_ERROR');
  if(r.errors.length)throw Error('RUNNER_SCANNER_ERROR');
  for(const f of r.results){
   if(!f||!ruleIds.includes(f.check_id??f.rule_id)||f.path!==files[i]||!f.path.startsWith(sourceDir+'/')||!Number.isSafeInteger(f.start?.line)||f.start.line<1||typeof f.extra?.severity!=='string')throw Error('RUNNER_UNSAFE_REPORT');
   findings.push(f);
  }
 }
 return freeze({component:'semgrep',status:'success',raw:{findings}});
}
function validate(input,projectId){
 keys(input,['approvalFile','sourceDir']);
 if(process.platform!=='linux'||process.arch!=='arm64'||process.getuid()===0||process.getgroups().some(g=>g===0||g===988))throw Error('SEMGREP_UNSUPPORTED_IDENTITY');
 const status=fs.readFileSync('/proc/self/status','utf8');if(!/^NoNewPrivs:\s+1$/m.test(status)||!/^CapEff:\s+0+$/m.test(status))throw Error('SEMGREP_UNSUPPORTED_IDENTITY');
 for(const p of ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml','/var/run/secrets/kubernetes.io/serviceaccount/token']){let readable=false;try{fs.accessSync(p,fs.constants.R_OK);readable=true;}catch{}if(readable)fail('Semgrep production authority accessible');}
 if(typeof input.approvalFile!=='string'||!/^\/var\/tmp\/security-manager-gitleaks-[a-zA-Z0-9_-]+\/semgrep-approval\.json$/.test(input.approvalFile))fail('Semgrep approval path');
 if(trusted(input.approvalFile).size>65536)fail('Semgrep approval budget');const a=JSON.parse(fs.readFileSync(input.approvalFile)),root=path.dirname(input.approvalFile);trusted(root,true);
 if(a.schemaVersion!==1||a.scope!=='SYNTHETIC_NON_RELEASE_SEMGREP_SCAN'||a.workspace!==root||a.executionUid!==process.getuid()||!Array.isArray(a.sources))fail('Semgrep approval identity/scope');
 const out=fs.lstatSync(a.outputRoot);if(a.outputRoot!==root+'/outputs'||fs.realpathSync(a.outputRoot)!==a.outputRoot||out.uid!==process.getuid()||(out.mode&0o077)||!out.isDirectory())fail('Semgrep private output domain');
 const source=a.sources.find(x=>x.projectId===projectId&&x.sourceDir===input.sourceDir);if(!source||!source.sourceDir.startsWith(root+'/source-')||!/^[a-f0-9]{40}$/.test(source.sourceRevision))fail('Semgrep unapproved source');
 const st=trusted(source.sourceDir,true);if(st.ino!==source.inode||st.dev!==source.device)fail('Semgrep source identity');
 const seen=[];function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,e.name),rel=path.relative(source.sourceDir,p);if(e.name==='.git'||e.name.startsWith('.semgrep')||e.name.startsWith('.gitleaks'))fail('Semgrep source config/history');if(e.isDirectory()){trusted(p,true);walk(p);}else{const s=trusted(p);if(s.size>65536||(s.mode&0o111))fail('Semgrep passive file budget');seen.push({path:rel,sha256:hashFile(p),bytes:s.size});}if(seen.length>16)fail('Semgrep source count');}}
 walk(source.sourceDir);seen.sort((a,b)=>a.path.localeCompare(b.path));if(digest(seen)!==source.fileManifestDigest)fail('Semgrep source content changed');
 const files=seen.filter(x=>x.path.endsWith('.java')).map(x=>path.join(source.sourceDir,x.path));if(!files.length)throw Error('SEMGREP_UNSUPPORTED_SOURCE');
 const identity=semgrepSourceIdentity(),lock=JSON.parse(fs.readFileSync(new URL('../scanner-tools.json',import.meta.url))),rows=lock.files.filter(x=>x.path==='semgrep/semgrep-core'||x.path.startsWith('semgrep/libs/'));
 if(a.tool.path!==root+'/semgrep/semgrep-core'||a.tool.libraryDirectory!==root+'/semgrep/libs'||a.tool.version!==lock.versions.semgrep)fail('Semgrep tool path/version');
 trusted(root+'/semgrep',true);trusted(root+'/semgrep/libs',true);
 if(JSON.stringify(fs.readdirSync(root+'/semgrep').sort())!==JSON.stringify(['libs','semgrep-core'])||JSON.stringify(fs.readdirSync(root+'/semgrep/libs').sort())!==JSON.stringify(rows.filter(x=>x.path.includes('/libs/')).map(x=>path.basename(x.path)).sort()))fail('Semgrep tool dependency whitelist');
 for(const row of rows){const p=root+'/'+row.path;if(trusted(p).size!==row.bytes||hashFile(p)!==row.sha256)fail('Semgrep fixed tool dependency changed');}
 if(a.rules.path!==root+'/rules.json'||hashFile(a.rules.path)!==identity.sourceHashes['infra/security/scan-rules.json'])fail('Semgrep rules changed');trusted(a.rules.path);
 return {a,source,files,identity,rules:JSON.parse(fs.readFileSync(a.rules.path)),toolSha256:rows.find(x=>x.path.endsWith('/semgrep-core')).sha256,
  executionIdentity:{uid:process.getuid(),gid:process.getgid(),groups:process.getgroups(),noNewPrivs:true,capEff:'0',environmentInherited:false,dockerReadable:false,kubeconfigReadable:false}};
}
async function command(bin,args,cwd,env,timeout,signal,onSpawn){
 if(signal?.aborted)throw Error('RUNNER_CANCELLED');if(timeout<=0)throw Error('RUNNER_TIMEOUT');
 const p=spawn(bin,args,{cwd,env,detached:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='',cause,timer,killer;
 const kill=s=>{if(p.pid)try{process.kill(-p.pid,s);}catch(e){if(e.code!=='ESRCH')throw e;}};
 const stop=r=>{if(cause)return;cause=r;kill('SIGTERM');killer=setTimeout(()=>kill('SIGKILL'),100);};const abort=()=>stop('RUNNER_CANCELLED');
 signal?.addEventListener('abort',abort,{once:true});
 try{
  const result=await new Promise((resolve,reject)=>{
   p.once('spawn',()=>{commands++;onSpawn?.();});p.once('error',()=>reject(Error('RUNNER_ERROR')));
   p.stdout.on('data',b=>{stdout+=b;if(Buffer.byteLength(stdout)>1024*1024)stop('RUNNER_OUTPUT_LIMIT');});p.stderr.on('data',b=>{stderr+=b;if(Buffer.byteLength(stderr)>65536)stop('RUNNER_OUTPUT_LIMIT');});
   p.once('close',(code,sig)=>resolve({code,signal:sig}));timer=setTimeout(()=>stop('RUNNER_TIMEOUT'),timeout);if(signal?.aborted)abort();
  });if(cause)throw Error(cause);return {...result,stdout,stderrSha256:sha(stderr)};
 }finally{clearTimeout(timer);clearTimeout(killer);signal?.removeEventListener('abort',abort);kill('SIGKILL');if(p.pid)try{process.kill(-p.pid,0);throw Error('RUNNER_CLEANUP_FAILED');}catch(e){if(e.code!=='ESRCH')throw e;}}
}
export async function executeRealSemgrep(plugin,input,{projectId,runId,signal}={}){
 const v=validate(input,projectId),dir=fs.mkdtempSync(path.join(v.a.outputRoot,'semgrep-scan-')),trace=[],reports=[],nativeReportTexts=[];let startedScan=false;
 const startedAt=new Date().toISOString(),deadline=Date.now()+plugin.timeout;
 const env={PATH:'/usr/bin:/bin',HOME:dir,TMPDIR:dir,LANG:'C',LD_LIBRARY_PATH:v.a.tool.libraryDirectory,SEMGREP_SEND_METRICS:'off',SEMGREP_ENABLE_VERSION_CHECK:'0'};
 try{
  const ver=await command(v.a.tool.path,['-version'],dir,env,Math.min(5000,deadline-Date.now()),signal);
  trace.push({argv:['-version'],exitStatus:ver.code,signal:ver.signal,stdoutSha256:sha(ver.stdout),stderrSha256:ver.stderrSha256});
  const versionMatch=ver.stdout.trim().match(/^semgrep-core version: (\d+\.\d+\.\d+) \(([a-f0-9]{10})\)$/);
  if(ver.code!==0||!versionMatch||versionMatch[1]!==v.a.tool.version)throw Error('RUNNER_TOOL_VERSION_ERROR');
  for(const file of v.files){
   const argv=['-rules',v.a.rules.path,'-lang','java','-json','-json_nodots','-j','1','-timeout','5','-max_memory','512',file];
   const r=await command(v.a.tool.path,argv,dir,env,deadline-Date.now(),signal,()=>{nativeCommands++;if(!startedScan){scans++;startedScan=true;}});
   trace.push({argv,exitStatus:r.code,signal:r.signal,stdoutSha256:sha(r.stdout),stderrSha256:r.stderrSha256});
   let native;try{native=JSON.parse(r.stdout);}catch{throw Error('RUNNER_REPORT_ERROR');}reports.push(native);nativeReportTexts.push({bytesUtf8:r.stdout,sha256:sha(r.stdout)});
   if(r.code!==0||r.signal)throw Error('RUNNER_SCANNER_ERROR');
  }
  const rawText=JSON.stringify({kind:'SemgrepNativeReportCollection',reports,nativeReportTexts}),fact=normalizeSemgrepNative(reports,v.source.sourceDir,v.files,v.rules.rules.map(x=>x.id));
  const old=classifySemgrep(fact.raw.findings),oldDecision=old.blocking.length?'FAIL':old.warnings.length?'WARN':'PASS';
  validate(input,projectId);
  const runtimeFacts={schemaVersion:1,kind:'CandidateRuntimeSourceFacts',classification:'REAL_CONTROLLED_EXECUTION',pluginId:'semgrep',validationRunId:runId,projectId,sourceRevision:v.source.sourceRevision,sourceDir:{path:v.source.sourceDir,inode:v.source.inode,device:v.source.device,fileManifestDigest:v.source.fileManifestDigest},tool:{version:v.a.tool.version,observedVersion:ver.stdout.trim(),sha256:v.toolSha256,platform:'linux/arm64'},rules:{sha256:v.identity.sourceHashes['infra/security/scan-rules.json'],ruleIds:v.rules.rules.map(x=>x.id),modified:false},sourceIdentity:v.identity,commands:trace,startedAt,completedAt:new Date().toISOString(),identity:v.executionIdentity,oldGate:{decision:oldDecision,productionAcceptance:old.blocking.length?'FAIL':'PASS',scope:'Existing finding classifier only; combined command-audit/Pod/lifecycle parent NOT_EXECUTED'},factDigest:digest(fact),rawReportDigest:sha(rawText),filesScanned:v.files.length,findingsCount:fact.raw.findings.length};
  return freeze({rawReport:JSON.parse(rawText),rawReportBytesUtf8:rawText,rawReportDigest:sha(rawText),fact,factDigest:digest(fact),oldDecision,runtimeFacts,evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',validationRunId:runId,sourceRevision:v.source.sourceRevision,toolSha256:v.toolSha256,rulesSha256:runtimeFacts.rules.sha256,rawReportDigest:sha(rawText),canonicalRuntime:false}],executionScope:'REAL_CONTROLLED_NON_RELEASE_NATIVE_SCAN',cleanup:{status:'VERIFIED',processGroupGone:true,privateReportDirectoryRemoved:true}});
 }catch(e){
  const rawText=reports.length?JSON.stringify({kind:'SemgrepNativeReportCollection',reports,nativeReportTexts}):null;
  e.candidateEvidence={classification:'REAL_CONTROLLED_EXECUTION_ERROR',commands:trace,startedAt,completedAt:new Date().toISOString(),nativeProcessesStarted:startedScan,rawReportBytesUtf8:rawText,rawReportDigest:rawText?sha(rawText):null};throw e;
 }finally{fs.rmSync(dir,{recursive:true});if(fs.existsSync(dir))throw Error('RUNNER_CLEANUP_FAILED');}
}
