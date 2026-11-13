// Local intake; fixed Gitleaks fixtures use the dedicated Linux SSH entry.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {randomUUID} from 'node:crypto';
import {root} from './data.mjs';
import {runCandidate} from '../core.mjs';
import {realManagedRegistry,realKyvernoRegistry,realSonarRegistry,realKubescapeRegistry,realZapRegistry,realProvenanceRegistry,realBuildProvenanceRegistry,realSopsRegistry} from '../registry.mjs';
import {routeResults,CONSUMERS} from '../router.mjs';
import {verifyArtifact,verifyResult} from '../result.mjs';
import {digest} from '../../summary-v2/codec.mjs';
import {linuxReady,runLinuxGitleaks,runLinuxCommitSnapshot,linuxHost,cleanIdentity} from './linux-gitleaks.mjs';
import {semgrepReady,runLinuxSemgrep,semgrepHost,semgrepIdentity} from './linux-semgrep.mjs';
import {cosignReady,runLinuxCosign,cosignHost,cosignIdentity} from './linux-cosign.mjs';
import {currentControls,writeControls,projectControls} from './controls.mjs';
import {sbomProjects,sbomReady} from '../sbom-real.mjs';
import {trivyProjects,trivyReady,trivyBlockedReason} from '../trivy-real.mjs';
import {kyvernoProjects,kyvernoReady,kyvernoBlockedReason,kyvernoUiCase} from '../kyverno-real.mjs';
import {sopsProjects,sopsReady,sopsBlockedReason,sopsUiCase} from '../sops-real.mjs';
import {buildProvenanceProjects,buildProvenanceUiCase} from '../build-provenance-real.mjs';
import {provenanceProjects,provenanceUiCase} from '../provenance-real.mjs';
import {zapProjects,zapReady,zapBlockedReason,zapUiCase} from '../zap-real.mjs';
import {kubescapeProjects,kubescapeReady,kubescapeBlockedReason,kubescapeUiCase} from '../kubescape-real.mjs';
import {sonarProjects,sonarReady,sonarBlockedReason,sonarUiCase} from '../sonar-real.mjs';
import {deliverRunToLoki} from './loki-delivery.mjs';
import {withReplayAudit} from './loki-replay.mjs';
const ids=['gitleaks','semgrep','cosign','sbom','trivy','kyverno','sonarqube','kubescape','zap','provenance','build-provenance','sops'],scenarios=['clean','controlled-finding'];
const directory=path.join(root,'.devsecops/security-view-runs-v1');
const identifier=/^web-[a-f0-9-]{36}$/;
let active=null;
const fault=(code,status=400)=>Object.assign(Error(code),{code,status});
function safeDir(p){const s=fs.lstatSync(p);if(fs.realpathSync(p)!==p||!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o077))throw fault('UNSAFE_RUN_DIRECTORY',503);}
function init(){const parent=path.dirname(directory),s=fs.lstatSync(parent);if(fs.realpathSync(parent)!==parent||!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o022))throw fault('UNSAFE_RUN_PARENT',503);if(!fs.existsSync(directory))fs.mkdirSync(directory,{mode:0o700});safeDir(directory);}
function read(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||s.nlink!==1||s.size>128*1024)throw fault('INVALID_RUN_RECORD',503);return JSON.parse(fs.readFileSync(fd,'utf8'));}finally{fs.closeSync(fd);}}
function save(p,value){const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function capabilities(projectId=null){
 const ready=linuxReady(),control=currentControls();
 const enabled=id=>control.settings.enabled&&control.settings.plugins[id].enabled&&(id!=='sbom'||!projectId||projectControls(projectId).effectiveEnabled);
 return {observedAt:new Date().toISOString(),platform:process.platform,arch:process.arch,uid:process.getuid(),groups:process.getgroups(),nodeVersion:process.version,
  executionLocation:ready||semgrepReady()||cosignReady()||trivyReady()?'LINUX_RESTRICTED':'MAC_ONLY',maxConcurrent:1,timeoutMs:90000,
  configurationRevision:control.revision,securityLevel:control.settings.securityLevel,
  plugins:ids.map(pluginId=>pluginId==='sbom'?{pluginId,state:!enabled(pluginId)?'DISABLED':sbomReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?'PLUGIN_DISABLED':sbomReady()?null:Object.values(sbomProjects())[0]?.blockedReason??'SBOM_EXECUTOR_UNAVAILABLE',toolVersion:'2.9.3',executionHost:'devops/192.168.64.11',executionIdentity:'security-sbom',scenarios:['clean'],projects:Object.keys(sbomProjects())}:pluginId==='trivy'?{pluginId,state:!enabled(pluginId)?'DISABLED':trivyReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):trivyReady()?null:trivyBlockedReason(),runner:'trivy-real',toolVersion:'0.76.2',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',executionIdentity:'security-trivy',scenarios:['clean'],projects:Object.keys(trivyProjects())}:pluginId==='kyverno'?{pluginId,state:!enabled(pluginId)?'DISABLED':kyvernoReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):kyvernoReady()?null:kyvernoBlockedReason(),runner:'kyverno-real',toolVersion:'1.36.1',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',executionIdentity:'security-kyverno',scenarios,projects:Object.keys(kyvernoProjects())}:pluginId==='sonarqube'?{pluginId,state:!enabled(pluginId)?'DISABLED':sonarReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):sonarReady()?null:sonarBlockedReason(),runner:'sonar-real',toolVersion:'7.2.0.5079',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',executionIdentity:'security-sonar',scenarios,projects:Object.entries(sonarProjects()).sort((a,b)=>Object.keys(b[1].cases??{}).length-Object.keys(a[1].cases??{}).length).map(([k])=>k)}:pluginId==='kubescape'?{pluginId,state:!enabled(pluginId)?'DISABLED':kubescapeReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):kubescapeReady()?null:kubescapeBlockedReason(),runner:'kubescape-real',toolVersion:'4.0.17',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',executionIdentity:'security-kubescape',scenarios,projects:Object.entries(kubescapeProjects()).sort((a,b)=>Object.keys(b[1].cases??{}).length-Object.keys(a[1].cases??{}).length).map(([k])=>k)}:pluginId==='zap'?{pluginId,state:!enabled(pluginId)?'DISABLED':zapReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):zapReady()?null:zapBlockedReason(),runner:'zap-real',toolVersion:'2.17.0',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',executionIdentity:'security-zap',scenarios,projects:Object.entries(zapProjects()).sort((a,b)=>Object.keys(b[1].cases??{}).length-Object.keys(a[1].cases??{}).length).map(([k])=>k)}:pluginId==='provenance'?{pluginId,state:!enabled(pluginId)?'DISABLED':'READY',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):null,runner:'provenance-real',toolVersion:null,toolVersionObservation:'OFFLINE_DSSE_ARCHIVED_PROOF',executionHost:'local/offline',executionIdentity:'local-operator',scenarios:['verified','rejected'],projects:Object.entries(provenanceProjects()).filter(([,p])=>Object.keys(p.cases??{}).length).map(([k])=>k)}:pluginId==='build-provenance'?{pluginId,state:!enabled(pluginId)?'DISABLED':'READY',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):null,runner:'build-provenance-real',toolVersion:null,toolVersionObservation:'OFFLINE_DSSE_ARCHIVED_PROOF',executionHost:'local/offline',executionIdentity:'local-operator',scenarios:['verified','rejected'],projects:Object.entries(buildProvenanceProjects()).filter(([,p])=>Object.keys(p.cases??{}).length).map(([k])=>k)}:pluginId==='sops'?{pluginId,state:!enabled(pluginId)?'DISABLED':sopsReady()?'READY':'BLOCKED',reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):sopsReady()?null:sopsBlockedReason(),runner:'sops-real',toolVersion:'3.13.3',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',executionIdentity:'security-sops',scenarios,projects:Object.entries(sopsProjects()).sort((a,b)=>Object.keys(b[1].cases??{}).length-Object.keys(a[1].cases??{}).length).map(([k])=>k)}:!enabled(pluginId)?{pluginId,state:'DISABLED',reason:control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED',configurationRevision:control.revision,configurationSource:control.source,scenarios}:pluginId==='gitleaks'&&ready?{pluginId,state:'READY',runner:'gitleaks-real',
   reason:null,toolVersion:'8.30.1',toolVersionObservation:'PINNED',fixtureStatus:'FIXED_NON_PRODUCTION_FIXTURES',
   executionHost:linuxHost,executionIdentity:cleanIdentity,scenarios}:
   pluginId==='semgrep'&&semgrepReady()?{pluginId,state:'READY',runner:'semgrep-real',reason:null,toolVersion:'1.182.1',toolVersionObservation:'PINNED',fixtureStatus:'FIXED_NON_PRODUCTION_FIXTURES',executionHost:semgrepHost,executionIdentity:semgrepIdentity,scenarios}:
   pluginId==='cosign'&&cosignReady()?{pluginId,state:'READY',runner:'cosign-real',reason:null,toolVersion:'3.1.4',toolVersionObservation:'PINNED',fixtureStatus:'FIXED_NON_PRODUCTION_SIGNATURE_FIXTURES',executionHost:cosignHost,executionIdentity:cosignIdentity,scenarios}:
   {pluginId,state:'BLOCKED',runner:realManagedRegistry().get(pluginId).runner,
   reason:'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY',toolVersion:null,toolVersionObservation:'NOT_EXECUTED',
   fixtureStatus:'NO_APPROVED_EXECUTOR',scenarios:pluginId==='gitleaks'?['clean']:scenarios})};
}
export function updateControls(input,reset=false){if(active)throw fault('RUN_ALREADY_ACTIVE',409);return writeControls(input,reset);}
export function validateRequest(value){if(!value||typeof value!=='object'||Array.isArray(value)||!['pluginId,scenarioId','pluginId,projectId,scenarioId'].includes(Object.keys(value).sort().join(','))||!ids.includes(value.pluginId)||!(scenarios.includes(value.scenarioId)||['provenance','build-provenance'].includes(value.pluginId)&&['verified','rejected'].includes(value.scenarioId))||['provenance','build-provenance'].includes(value.pluginId)&&!['verified','rejected'].includes(value.scenarioId))throw fault('INVALID_FIXED_RUN_REQUEST');if(value.pluginId==='sbom'&&(!sbomProjects()[value.projectId]||value.scenarioId!=='clean')||value.pluginId==='trivy'&&(!trivyProjects()[value.projectId]||value.scenarioId!=='clean')||value.pluginId==='kyverno'&&!kyvernoProjects()[value.projectId]||value.pluginId==='sonarqube'&&!sonarProjects()[value.projectId]||value.pluginId==='kubescape'&&!kubescapeProjects()[value.projectId]||value.pluginId==='zap'&&!zapProjects()[value.projectId]||value.pluginId==='provenance'&&!provenanceProjects()[value.projectId]||value.pluginId==='build-provenance'&&!buildProvenanceProjects()[value.projectId]||value.pluginId==='sops'&&!sopsProjects()[value.projectId]||value.pluginId!=='sbom'&&value.pluginId!=='trivy'&&value.pluginId!=='kyverno'&&value.pluginId!=='sonarqube'&&value.pluginId!=='kubescape'&&value.pluginId!=='zap'&&value.pluginId!=='provenance'&&value.pluginId!=='build-provenance'&&value.pluginId!=='sops'&&value.projectId!==undefined)throw fault('PROJECT_NOT_AUTHORIZED',403);return value;}
export function getRun(runId){
 if(!identifier.test(runId))throw fault('INVALID_RUN_ID');init();const dir=path.join(directory,runId);
 if(!fs.existsSync(dir))throw fault('RUN_NOT_FOUND',404);safeDir(dir);const request=read(path.join(dir,'request.json'));
 if(!fs.existsSync(path.join(dir,'result.json'))){
  // Read the sealed failure without rewriting the original request or evidence.
  if(active!==runId&&request.pluginId==='sbom'&&fs.existsSync(path.join(dir,'artifact/candidate-seal.json'))){
   const seal=read(path.join(dir,'artifact/candidate-seal.json')),sealDigest=digest(seal);verifyArtifact(path.join(dir,'artifact'),sealDigest);
   const p=read(path.join(dir,'artifact/sbom.result.json'));verifyResult(p);
   if(p.runId!==runId||p.projectId!==request.projectId)throw fault('RUN_BINDING_MISMATCH',503);
   if(p.executionStatus==='ERROR')return {...request,state:'ERROR',evidenceClass:'NOT_TESTED',reason:p.failureReason,policyDecision:p.policyDecision,evaluationCount:p.evaluationCount,resultDigest:p.resultDigest,artifactDigest:sealDigest,completedAt:p.completedAt,recordSource:'SEALED_FAILURE_ARTIFACT',cleanup:p.cleanup?.status??'NOT_VERIFIED'};
  }
  return {...request,state:active===runId?'RUNNING':'ERROR',evidenceClass:'NOT_TESTED',reason:active===runId?null:'SERVER_INTERRUPTED_BEFORE_COMPLETION',policyDecision:null};
 }
 const result=read(path.join(dir,'result.json'));const {auditDigest,...body}=result;
 if(digest(body)!==auditDigest)throw fault('RUN_RECORD_DIGEST_MISMATCH',503);
 if(result.artifactDigest){verifyArtifact(path.join(dir,'artifact'),result.artifactDigest);const p=read(path.join(dir,'artifact',request.pluginId+'.result.json'));verifyResult(p);if(p.resultDigest!==result.resultDigest||p.runId!==runId)throw fault('RUN_BINDING_MISMATCH',503);}
 const diagnosticPath=path.join(dir,'execution-diagnostic.json');
 if(result.state==='ERROR'&&fs.existsSync(diagnosticPath)){
  const {diagnosticDigest,...d}=read(diagnosticPath);
  if(digest(d)!==diagnosticDigest||d.runId!==runId||d.relatedResultAuditDigest!==auditDigest||!Array.isArray(d.stages)||d.stages.length>32)throw fault('EXECUTION_DIAGNOSTIC_BINDING',503);
  return {...result,executionDiagnostic:d};
 }
 const replayPath=path.join(dir,'loki-replay-audit.json');
 return fs.existsSync(replayPath)?withReplayAudit(result,read(replayPath)):result;
}
export function recentRuns(){init();return fs.readdirSync(directory).filter(n=>identifier.test(n)).sort().map(n=>getRun(n)).sort((a,b)=>b.startedAt.localeCompare(a.startedAt));}
export function submit(value,ciContext=null){
 validateRequest(value);init();
 if(active)throw fault('RUN_ALREADY_ACTIVE',409);
 if(fs.readdirSync(directory).length>=100)throw fault('LOCAL_RECORD_BUDGET_EXHAUSTED',429);
 const control=currentControls(),project=value.pluginId==='sbom'?projectControls(value.projectId):ciContext?projectControls(ciContext.projectId):null;
 const configurationSnapshot={revision:control.revision,updatedAt:control.updatedAt,settings:control.settings,source:control.source,configurationOrigins:control.effectiveConfig.configurationOrigins,effectiveConfigDigest:project?.effectiveConfig.effectiveConfigDigest??control.effectiveConfig.effectiveConfigDigest,...(project?{project}: {})};
 const enabled=control.settings.enabled&&control.settings.plugins[value.pluginId].enabled&&(project?.effectiveEnabled??true);
 const runId='web-'+randomUUID(),dir=path.join(directory,runId);fs.mkdirSync(dir,{mode:0o700});safeDir(dir);
 const remote=value.pluginId==='gitleaks'&&linuxReady()||value.pluginId==='semgrep'&&semgrepReady()||value.pluginId==='cosign'&&cosignReady()||value.pluginId==='sbom'&&sbomReady()||value.pluginId==='trivy'&&trivyReady()||value.pluginId==='kyverno'&&kyvernoReady()||value.pluginId==='sonarqube'&&sonarReady()||value.pluginId==='kubescape'&&kubescapeReady()||value.pluginId==='zap'&&zapReady()||value.pluginId==='sops'&&sopsReady();
 const request={runId,...value,...(ciContext?{projectId:ciContext.projectId,ciContext}:{}),configurationSnapshot,securityLevel:control.settings.securityLevel,startedAt:new Date().toISOString(),kind:'LocalValidationRequest',executionLocation:!enabled?'NO_EXECUTION':remote?'LINUX_RESTRICTED':'MAC_ONLY'};
 save(path.join(dir,'request.json'),request);active=runId;
 setImmediate(async()=>{
  const start=performance.now();const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),ciContext?.sourceMode==='REAL_COMMIT_SNAPSHOT'?150000:value.pluginId==='trivy'?225000:value.pluginId==='kyverno'?60000:value.pluginId==='sonarqube'?195000:value.pluginId==='kubescape'?1515000:value.pluginId==='zap'?255000:value.pluginId==='provenance'?45000:value.pluginId==='build-provenance'?45000:value.pluginId==='sops'?135000:value.pluginId==='sbom'?90000:30000);let result,budget=null,attempted=false;
  try{
   if(!enabled&&value.pluginId==='sbom'){result={...request,state:'DISABLED',evidenceClass:'NOT_TESTED',reason:!control.settings.enabled?'MASTER_DISABLED':!control.settings.plugins.sbom.enabled?'PLUGIN_DISABLED':'PROJECT_PLUGIN_DISABLED',scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null};return;}
   if(!enabled){
    const registry=realManagedRegistry();
    const run=await runCandidate({registry,runId,projectId:'web-controlled-fixture',context:{platform:process.platform,capabilities:{}},inputs:{},config:{security:{enabled:control.settings.enabled,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}},output:path.join(dir,'artifact')});
    const selected=run.gate[value.pluginId];
    if(selected.executionStatus!=='DISABLED'||selected.evaluationCount!==0||selected.policyDecision!==null)throw fault('DISABLED_CONTRACT_FAILED');
    result={...request,state:'DISABLED',evidenceClass:'NOT_TESTED',managerExecutionStatus:'DISABLED',reason:control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED',scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact',value.pluginId+'.result.json'))};return;
   }
   if(value.pluginId==='sbom'){
    const cfg=sbomProjects()[value.projectId],registry=realManagedRegistry();if(cfg.blockedReason)throw fault(cfg.blockedReason);attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{SBOM_FILE:{state:'AVAILABLE'}}},inputs:{sbom:{fixtureId:cfg.fixtureId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='sbom'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.sbom,f=selected.runtimeFacts;
    const diagnostic=f?.diagnostic??(fs.existsSync(path.join(dir,'artifact/sbom.execution-error.json'))?read(path.join(dir,'artifact/sbom.execution-error.json')).diagnostic:null);
    const prerequisiteBlocked=diagnostic?.generationInvocations===0&&diagnostic.error?.endsWith('_BLOCKED');
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:prerequisiteBlocked?'BLOCKED':selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f||diagnostic?.generationInvocations===1,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/sbom.result.json')),reason:prerequisiteBlocked?diagnostic.error:selected.failureReason,
     executionDiagnostic:diagnostic,scannerExitCode:f?.exitCode??diagnostic?.exitCode??null,toolVersion:f?.tool.version??null,executionIdentity:'security-sbom',executionHost:'devops/192.168.64.11',sourceArtifactSha256:f?.sourceArtifactSha256??null,sbomSha256:f?.sbomSha256??null,sbomFormat:f?.format??null,sbomSpecVersion:f?.specVersion??null,componentCount:f?.componentCount??null,scope:cfg.scope,commitSha:cfg.commitSha,buildId:cfg.buildId,scannerStartedAt:f?.startedAt??null,scannerCompletedAt:f?.completedAt??null,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='trivy'){
    const cfg=trivyProjects()[value.projectId],registry=realManagedRegistry(),blocked=trivyBlockedReason();
    if(blocked){result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'security-trivy',executionHost:'devops/192.168.1.58',toolVersion:'0.76.2'};return;}
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{IMAGE_REF:{state:'AVAILABLE'},FRESH_DB:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{trivy:{targetId:cfg.targetId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='trivy'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.trivy,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/trivy.execution-error.json'))?read(path.join(dir,'artifact/trivy.execution-error.json')).diagnostic:null;
    const gateBlocked=typeof diagnostic?.error==='string'&&diagnostic.error.endsWith('_BLOCKED');
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:gateBlocked?'BLOCKED':selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/trivy.result.json')),reason:gateBlocked?diagnostic.error:selected.failureReason,
     executionDiagnostic:diagnostic,db:f?.db?.map(d=>({name:d.name,version:d.metadata?.Version,updatedAt:d.metadata?.UpdatedAt,nextUpdate:d.metadata?.NextUpdate,metadataSha256:d.metadataSha256}))??null,findingCount:f?.findingCount??null,toolVersion:f?.toolVersion??null,toolSha256:f?.toolSha256??null,indexDigest:cfg.indexDigest,platformDigest:cfg.platformDigest,executionIdentity:'security-trivy',executionHost:'devops/192.168.1.58',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='kyverno'){
    const cfg=kyvernoProjects()[value.projectId],registry=realKyvernoRegistry(),blocked=kyvernoBlockedReason(),caseId=kyvernoUiCase(cfg,value.scenarioId);
    if(blocked){result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'security-kyverno',executionHost:'devops/192.168.1.58',toolVersion:'1.36.1',caseId};return;}
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{CLUSTER_ACCESS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{kyverno:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='kyverno'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.kyverno,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/kyverno.execution-error.json'))?read(path.join(dir,'artifact/kyverno.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/kyverno.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,allowed:f?.allowed??null,policyName:cfg.policy,namespace:cfg.namespace,image:cfg.cases[caseId].image,toolVersion:f?.toolVersion??null,toolSha256:f?.toolSha256??null,executionIdentity:'security-kyverno',executionHost:'devops/192.168.1.58',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='sonarqube'){
    const cfg=sonarProjects()[value.projectId],registry=realSonarRegistry(),blocked=sonarBlockedReason(),caseId=sonarUiCase(cfg,value.scenarioId);
    if(blocked){result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'security-sonar',executionHost:'devops/192.168.1.58',toolVersion:'7.2.0.5079',caseId};return;}
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{RUNTIME_TARGET:{state:'AVAILABLE'},CREDENTIALS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{sonarqube:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='sonarqube'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.sonarqube,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/sonarqube.execution-error.json'))?read(path.join(dir,'artifact/sonarqube.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/sonarqube.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,gateStatus:f?.gateStatus??null,analysisId:f?.analysisId??null,componentKey:f?.componentKey??null,toolVersion:f?.toolVersion??'7.2.0.5079',toolSha256:f?.toolSha256??null,executionIdentity:'security-sonar',executionHost:'devops/192.168.1.58',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='kubescape'){
    const cfg=kubescapeProjects()[value.projectId],registry=realKubescapeRegistry(),blocked=kubescapeBlockedReason(),caseId=kubescapeUiCase(cfg,value.scenarioId);
    if(blocked){result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'security-kubescape',executionHost:'devops/192.168.1.58',toolVersion:'4.0.17',caseId};return;}
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{CLUSTER_ACCESS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{kubescape:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='kubescape'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.kubescape,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/kubescape.execution-error.json'))?read(path.join(dir,'artifact/kubescape.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/kubescape.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,findings:f?.findings??null,failedControls:f?.failedControls??null,highRiskFindings:f?.highRiskFindings??null,auditDisposition:f?.auditDisposition??null,violating:f?.violating??null,toolVersion:f?.toolVersion??'4.0.17',toolSha256:f?.toolSha256??null,executionIdentity:'security-kubescape',executionHost:'devops/192.168.1.58',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='zap'){
    const cfg=zapProjects()[value.projectId],registry=realZapRegistry(),blocked=zapBlockedReason(),caseId=zapUiCase(cfg,value.scenarioId),level=value.scenarioId==='clean'?'standard':'strict';
    if(blocked){result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'security-zap',executionHost:'devops/192.168.1.58',toolVersion:'2.17.0',caseId};return;}
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{RUNTIME_TARGET:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{zap:{targetId:cfg.targetId,caseId,policyLevel:level}},config:{security:{enabled:true,globalMode:'audit',securityLevel:level,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='zap'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.zap,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/zap.execution-error.json'))?read(path.join(dir,'artifact/zap.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/zap.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,policyLevel:level,alertsTotal:f?.alertsTotal??null,riskCounts:f?.riskCounts??null,reportSha256:f?.reportSha256??null,targetImage:f?.targetImage??null,toolVersion:f?.toolVersion??'2.17.0',toolSha256:f?.toolSha256??null,executionIdentity:'security-zap',executionHost:'devops/192.168.1.58',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='provenance'){
    const cfg=provenanceProjects()[value.projectId],registry=realProvenanceRegistry(),caseId=provenanceUiCase(cfg,value.scenarioId);
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{PROVENANCE_METADATA:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{'provenance':{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='provenance'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.provenance,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/provenance.execution-error.json'))?read(path.join(dir,'artifact/provenance.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/provenance.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,subjectImage:f?.subjectImage??null,commit:f?.commit??null,buildNumber:f?.buildNumber??null,envelopeSha256:f?.envelopeSha256??null,toolVersion:f?.toolVersion??null,toolSha256:f?.toolSha256??null,executionIdentity:'local-operator',executionHost:'local/offline',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='build-provenance'){
    const cfg=buildProvenanceProjects()[value.projectId],registry=realBuildProvenanceRegistry(),caseId=buildProvenanceUiCase(cfg,value.scenarioId);
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{BUILD_METADATA:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{'build-provenance':{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='build-provenance'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate['build-provenance'],f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/build-provenance.execution-error.json'))?read(path.join(dir,'artifact/build-provenance.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/build-provenance.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,subjectImage:f?.subjectImage??null,commit:f?.commit??null,buildNumber:f?.buildNumber??null,jarSha256:f?.jarSha256??null,envelopeSha256:f?.envelopeSha256??null,exitCode:f?.exitCode??null,toolVersion:f?.toolVersion??null,toolSha256:f?.toolSha256??null,executionIdentity:'local-operator',executionHost:'local/offline',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(value.pluginId==='sops'){
    const cfg=sopsProjects()[value.projectId],registry=realSopsRegistry(),blocked=sopsBlockedReason(),caseId=sopsUiCase(cfg,value.scenarioId);
    if(blocked){result={...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'security-sops',executionHost:'devops/192.168.1.58',toolVersion:'3.13.3',caseId};return;}
    attempted=true;
    const run=await runCandidate({registry,runId,projectId:value.projectId,context:{platform:process.platform,capabilities:{CREDENTIALS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{sops:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='sops'}]))}},output:path.join(dir,'artifact'),signal:controller.signal});
    const selected=run.gate.sops,f=selected.runtimeFacts;
    const diagnostic=fs.existsSync(path.join(dir,'artifact/sops.execution-error.json'))?read(path.join(dir,'artifact/sops.execution-error.json')).diagnostic:null;
    fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
    const routed=routeResults({run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
    result={...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/sops.result.json')),reason:selected.failureReason,
     executionDiagnostic:diagnostic,caseId,storeModel:f?.storeModel??null,rbacModel:f?.rbacModel??null,cipherTargets:Array.isArray(f?.cipherFacts)?f.cipherFacts.length:null,toolVersion:f?.toolVersion??'3.13.3',toolSha256:f?.toolSha256??null,executionIdentity:'security-sops',executionHost:'devops/192.168.1.58',router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'};return;
   }
   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');
   if(value.pluginId==='gitleaks'){
    if(!remote)throw fault('LINUX_GITLEAKS_NOT_CONFIGURED_BLOCKED');
    attempted=true;
    result={...request,...await (ciContext?.sourceMode==='REAL_COMMIT_SNAPSHOT'?runLinuxCommitSnapshot(ciContext,runId,dir,controller.signal,control.settings.securityLevel):runLinuxGitleaks(value.scenarioId,runId,dir,controller.signal,control.settings.securityLevel)),
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
   const registry=realManagedRegistry();
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
   if(result?.state==='COMPLETED'&&result.evidenceClass==='REAL'){
    try{result.lokiDelivery=await deliverRunToLoki(result,dir);}
    catch(e){result.lokiDelivery={consumerId:'loki-candidate',automatic:true,state:'FAILED',queryState:'NOT_VERIFIED',runId,
      resultDigest:result.resultDigest,reason:/^[A-Z_]{3,80}$/.test(e.code??'')?e.code:'LOKI_AUTO_DELIVERY_FAILED'};}
   }
   try{const body={...result,completedAt:new Date().toISOString(),durationMs:Math.round(performance.now()-start),cleanup:result?.cleanup??(attempted?'NOT_VERIFIED':'NO_SCANNER_STARTED'),releaseCount:0,rolloutCount:0};save(path.join(dir,'result.json'),{...body,auditDigest:digest(body)});}catch{console.error('LOCAL_RUN_PERSISTENCE_FAILED');}finally{active=null;}
  }
 });
 return {...request,state:'QUEUED',evidenceClass:'NOT_TESTED'};
}
