// Local intake; fixed Gitleaks fixtures use the dedicated Linux SSH entry.
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
import {linuxReady,runLinuxGitleaks,linuxHost,cleanIdentity} from './linux-gitleaks.mjs';
import {semgrepReady,runLinuxSemgrep,semgrepHost,semgrepIdentity} from './linux-semgrep.mjs';
import {cosignReady,runLinuxCosign,cosignHost,cosignIdentity} from './linux-cosign.mjs';
import {currentControls,writeControls} from './controls.mjs';
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
 const ready=linuxReady(),control=currentControls();
 const enabled=id=>control.settings.enabled&&control.settings.plugins[id].enabled;
 return {observedAt:new Date().toISOString(),platform:process.platform,arch:process.arch,uid:process.getuid(),groups:process.getgroups(),nodeVersion:process.version,
  executionLocation:ready||semgrepReady()||cosignReady()?'LINUX_RESTRICTED':'MAC_ONLY',maxConcurrent:1,timeoutMs:30000,
  configurationRevision:control.revision,securityLevel:control.settings.securityLevel,
  plugins:ids.map(pluginId=>!enabled(pluginId)?{pluginId,state:'DISABLED',reason:control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED',configurationRevision:control.revision,configurationSource:control.source,scenarios}:pluginId==='gitleaks'&&ready?{pluginId,state:'READY',runner:'gitleaks-real',
   reason:null,toolVersion:'8.30.1',toolVersionObservation:'PINNED',fixtureStatus:'FIXED_NON_PRODUCTION_FIXTURES',
   executionHost:linuxHost,executionIdentity:cleanIdentity,scenarios}:
   pluginId==='semgrep'&&semgrepReady()?{pluginId,state:'READY',runner:'semgrep-real',reason:null,toolVersion:'1.182.1',toolVersionObservation:'PINNED',fixtureStatus:'FIXED_NON_PRODUCTION_FIXTURES',executionHost:semgrepHost,executionIdentity:semgrepIdentity,scenarios}:
   pluginId==='cosign'&&cosignReady()?{pluginId,state:'READY',runner:'cosign-real',reason:null,toolVersion:'3.1.4',toolVersionObservation:'PINNED',fixtureStatus:'FIXED_NON_PRODUCTION_SIGNATURE_FIXTURES',executionHost:cosignHost,executionIdentity:cosignIdentity,scenarios}:
   {pluginId,state:'BLOCKED',runner:realThreePluginsRegistry().get(pluginId).runner,
   reason:'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY',toolVersion:null,toolVersionObservation:'NOT_EXECUTED',
   fixtureStatus:'NO_APPROVED_EXECUTOR',scenarios:pluginId==='gitleaks'?['clean']:scenarios})};
}
export function updateControls(input,reset=false){if(active)throw fault('RUN_ALREADY_ACTIVE',409);return writeControls(input,reset);}
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
 const control=currentControls();
 const configurationSnapshot={revision:control.revision,updatedAt:control.updatedAt,settings:control.settings,source:control.source,configurationOrigins:control.effectiveConfig.configurationOrigins,effectiveConfigDigest:control.effectiveConfig.effectiveConfigDigest};
 const enabled=control.settings.enabled&&control.settings.plugins[value.pluginId].enabled;
 const runId='web-'+randomUUID(),dir=path.join(directory,runId);fs.mkdirSync(dir,{mode:0o700});safeDir(dir);
 const remote=value.pluginId==='gitleaks'&&linuxReady()||value.pluginId==='semgrep'&&semgrepReady()||value.pluginId==='cosign'&&cosignReady();
 const request={runId,...value,configurationSnapshot,securityLevel:control.settings.securityLevel,startedAt:new Date().toISOString(),kind:'LocalValidationRequest',executionLocation:!enabled?'NO_EXECUTION':remote?'LINUX_RESTRICTED':'MAC_ONLY'};
 save(path.join(dir,'request.json'),request);active=runId;
 setImmediate(async()=>{
  const start=performance.now();const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),30000);let result,budget=null,attempted=false;
  try{
   if(!enabled){
    const registry=realThreePluginsRegistry();
    const run=await runCandidate({registry,runId,projectId:'web-controlled-fixture',context:{platform:process.platform,capabilities:{}},inputs:{},config:{security:{enabled:control.settings.enabled,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}},output:path.join(dir,'artifact')});
    const selected=run.gate[value.pluginId];
    if(selected.executionStatus!=='DISABLED'||selected.evaluationCount!==0||selected.policyDecision!==null)throw fault('DISABLED_CONTRACT_FAILED');
    result={...request,state:'DISABLED',evidenceClass:'NOT_TESTED',managerExecutionStatus:'DISABLED',reason:control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED',scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact',value.pluginId+'.result.json'))};return;
   }
   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');
   if(value.pluginId==='gitleaks'){
    if(!remote)throw fault('LINUX_GITLEAKS_NOT_CONFIGURED_BLOCKED');
    attempted=true;
    result={...request,...await runLinuxGitleaks(value.scenarioId,runId,dir,controller.signal,control.settings.securityLevel),
     source:path.relative(root,path.join(dir,'artifact','gitleaks.result.json'))};
    return;
   }
   if(value.pluginId==='semgrep'){
    if(!remote)throw fault('LINUX_SEMGREP_NOT_CONFIGURED_BLOCKED');
    attempted=true;
    result={...request,...await runLinuxSemgrep(value.scenarioId,runId,dir,controller.signal,control.settings.securityLevel),source:path.relative(root,path.join(dir,'artifact','semgrep.result.json'))};
    return;
   }
   if(value.pluginId==='cosign'){
    if(!remote)throw fault('LINUX_COSIGN_NOT_CONFIGURED_BLOCKED');
    attempted=true;
    result={...request,...await runLinuxCosign(value.scenarioId,runId,dir,controller.signal,control.settings.securityLevel),source:path.relative(root,path.join(dir,'artifact','cosign.result.json'))};
    return;
   }
   const disk=fs.statfsSync(directory);budget={load1:os.loadavg()[0],cpuCount:os.cpus().length,freeMemory:os.freemem(),freeDisk:Number(disk.bavail)*Number(disk.bsize)};
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
  }catch(e){result={...request,state:e.code?.includes('BLOCKED')||e.code==='LOCAL_MAC_IDENTITY_REQUIRED'?'BLOCKED':'ERROR',evidenceClass:'NOT_TESTED',reason:/^[A-Z_]+$/.test(e.code??'')?e.code:'LOCAL_VALIDATION_ERROR',policyDecision:null,evaluationCount:0,resultDigest:null,scannerExecuted:attempted?null:false,budget};}
  finally{
   clearTimeout(timer);
   try{const body={...result,completedAt:new Date().toISOString(),durationMs:Math.round(performance.now()-start),cleanup:result?.cleanup??(attempted?'NOT_VERIFIED':'NO_SCANNER_STARTED'),releaseCount:0,rolloutCount:0};save(path.join(dir,'result.json'),{...body,auditDigest:digest(body)});}catch{console.error('LOCAL_RUN_PERSISTENCE_FAILED');}finally{active=null;}
  }
 });
 return {...request,state:'QUEUED',evidenceClass:'NOT_TESTED'};
}
