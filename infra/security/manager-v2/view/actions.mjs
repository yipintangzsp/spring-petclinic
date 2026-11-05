// Local intake only: preserve the existing Linux-only runner trust contract.
// No Darwin emulation, remote fallback, shell, fixture generation or downloads.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {randomUUID} from 'node:crypto';
import {root} from './data.mjs';
import {runCandidate} from '../core.mjs';
import {realThreePluginsRegistry} from '../registry.mjs';
import {routeResults,CONSUMERS} from '../router.mjs';
import {verifyArtifact,verifyResult} from '../result.mjs';
import {digest} from '../../summary-v2/codec.mjs';
const ids=['gitleaks','semgrep','cosign'],scenarios=['clean','controlled-finding'];
const directory=path.join(root,'.devsecops/security-view-runs-v1');
const identifier=/^web-[a-f0-9-]{36}$/;
let active=null;
const fault=(code,status=400)=>Object.assign(Error(code),{code,status});
function safeDir(p){const s=fs.lstatSync(p);if(fs.realpathSync(p)!==p||!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o077))throw fault('UNSAFE_RUN_DIRECTORY',503);}
function init(){const parent=path.dirname(directory),s=fs.lstatSync(parent);if(fs.realpathSync(parent)!==parent||!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o022))throw fault('UNSAFE_RUN_PARENT',503);if(!fs.existsSync(directory))fs.mkdirSync(directory,{mode:0o700});safeDir(directory);}
function read(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||s.nlink!==1||s.size>128*1024)throw fault('INVALID_RUN_RECORD',503);return JSON.parse(fs.readFileSync(fd,'utf8'));}finally{fs.closeSync(fd);}}
function save(p,value){const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function capabilities(){
 return {platform:process.platform,arch:process.arch,uid:process.getuid(),groups:process.getgroups(),nodeVersion:process.version,
  executionLocation:'MAC_ONLY',maxConcurrent:1,timeoutMs:30000,
  plugins:ids.map(pluginId=>({pluginId,state:'BLOCKED',runner:realThreePluginsRegistry().get(pluginId).runner,
   reason:'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY',toolVersion:null,toolVersionObservation:'NOT_EXECUTED',
   fixtureStatus:'NO_APPROVED_MAC_FIXTURE',scenarios}))};
}
export function validateRequest(value){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='pluginId,scenarioId'||!ids.includes(value.pluginId)||!scenarios.includes(value.scenarioId))throw fault('INVALID_FIXED_RUN_REQUEST');return value;}
export function getRun(runId){
 if(!identifier.test(runId))throw fault('INVALID_RUN_ID');init();const dir=path.join(directory,runId);
 if(!fs.existsSync(dir))throw fault('RUN_NOT_FOUND',404);safeDir(dir);const request=read(path.join(dir,'request.json'));
 if(!fs.existsSync(path.join(dir,'result.json')))return {...request,state:active===runId?'RUNNING':'ERROR',evidenceClass:'NOT_TESTED',reason:active===runId?null:'SERVER_INTERRUPTED_BEFORE_COMPLETION',policyDecision:null};
 const result=read(path.join(dir,'result.json'));const {auditDigest,...body}=result;
 if(digest(body)!==auditDigest)throw fault('RUN_RECORD_DIGEST_MISMATCH',503);
 if(result.artifactDigest){verifyArtifact(path.join(dir,'artifact'),result.artifactDigest);const p=read(path.join(dir,'artifact',request.pluginId+'.result.json'));verifyResult(p);if(p.resultDigest!==result.resultDigest||p.runId!==runId)throw fault('RUN_BINDING_MISMATCH',503);}
 return result;
}
export function recentRuns(){init();return fs.readdirSync(directory).filter(n=>identifier.test(n)).sort().map(n=>getRun(n)).sort((a,b)=>b.startedAt.localeCompare(a.startedAt)).slice(0,20);}
export function submit(value){
 validateRequest(value);init();
 if(active)throw fault('RUN_ALREADY_ACTIVE',409);
 if(fs.readdirSync(directory).length>=100)throw fault('LOCAL_RECORD_BUDGET_EXHAUSTED',429);
 const runId='web-'+randomUUID(),dir=path.join(directory,runId);fs.mkdirSync(dir,{mode:0o700});safeDir(dir);
 const request={runId,...value,startedAt:new Date().toISOString(),kind:'LocalValidationRequest',executionLocation:'MAC_ONLY'};
 save(path.join(dir,'request.json'),request);active=runId;
 setImmediate(async()=>{
  const start=performance.now();const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),30000);let result,budget;
  try{
   const disk=fs.statfsSync(directory);budget={load1:os.loadavg()[0],cpuCount:os.cpus().length,freeMemory:os.freemem(),freeDisk:Number(disk.bavail)*Number(disk.bsize)};
   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');
   if(budget.load1>budget.cpuCount*.75||budget.freeMemory<512*1024**2||budget.freeDisk<512*1024**2)throw fault('LOCAL_RESOURCE_BUDGET_BLOCKED');
   const registry=realThreePluginsRegistry();
   // Actual platform, unavailable capabilities, no fabricated Linux identity or facts.
   const run=await runCandidate({registry,runId,projectId:'web-controlled-fixture',context:{platform:process.platform,capabilities:{}},inputs:{},
    config:{security:{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id===value.pluginId}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
   const selected=run.gate[value.pluginId];
   if(selected.executionStatus!=='UNSUPPORTED'||selected.policyDecision!==null||selected.evaluationCount!==0)throw fault('UNEXPECTED_MAC_PREFLIGHT_STATE');
   const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,definitions:CONSUMERS.filter(c=>c.consumerId==='dry-run')});
   result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY',
    managerExecutionStatus:selected.executionStatus,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,
    artifactDigest:run.artifact.sealDigest,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision,resultDigest:r.resultDigests[value.pluginId]})),
    source:path.relative(root,path.join(dir,'artifact',value.pluginId+'.result.json')),budget,scannerExecuted:false};
  }catch(e){result={...request,state:e.code?.includes('BLOCKED')||e.code==='LOCAL_MAC_IDENTITY_REQUIRED'?'BLOCKED':'ERROR',evidenceClass:'NOT_TESTED',reason:/^[A-Z_]+$/.test(e.code??'')?e.code:'LOCAL_VALIDATION_ERROR',policyDecision:null,evaluationCount:0,resultDigest:null,scannerExecuted:false,budget};}
  finally{
   clearTimeout(timer);
   try{const body={...result,completedAt:new Date().toISOString(),durationMs:Math.round(performance.now()-start),cleanup:'NO_SCANNER_STARTED',releaseCount:0,rolloutCount:0};save(path.join(dir,'result.json'),{...body,auditDigest:digest(body)});}catch{console.error('LOCAL_RUN_PERSISTENCE_FAILED');}finally{active=null;}
  }
 });
 return {...request,state:'QUEUED',evidenceClass:'NOT_TESTED'};
}
