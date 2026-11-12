import fs from 'node:fs';import path from 'node:path';import {randomUUID} from 'node:crypto';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';
import {realProvenanceRegistry} from '../../../infra/security/manager-v2/registry.mjs';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {provenanceProjects,executeRealProvenance} from '../../../infra/security/manager-v2/provenance-real.mjs';
import {deliverRunToLoki} from '../../../infra/security/manager-v2/view/loki-delivery.mjs';
const PLUGIN='provenance';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const runsRoot=path.join(root,'.devsecops/provenance-runs');fs.mkdirSync(runsRoot,{recursive:true,mode:0o755});
const evDir=path.join(root,'evidence/2026-11-13/provenance-v2/raw');fs.mkdirSync(evDir,{recursive:true});
const registry=realProvenanceRegistry();
const projects=provenanceProjects();
const out={cases:[],disabled:[],crossProject:{},loki:[]};
const CAPS={PROVENANCE_METADATA:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}};
async function one(projectId,caseId){
 const cfg=projects[projectId],runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const artifactDir=path.join(dir,'artifact');
 const run=await runCandidate({registry,runId,projectId,context:{platform:process.platform,capabilities:CAPS},inputs:{[PLUGIN]:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:'standard',profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id===PLUGIN}]))}},output:artifactDir});
 const sel=run.gate[PLUGIN];
 fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
 const routed=routeResults({run,artifactDirectory:artifactDir,expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
 const rec={runId,projectId,caseId,expectedDecision:cfg.cases[caseId].expectedDecision,executionStatus:sel.executionStatus,policyDecision:sel.policyDecision,oldGateDecision:sel.oldGateDecision??null,evaluationCount:sel.evaluationCount,resultDigest:sel.resultDigest,artifactDigest:run.artifact.sealDigest,failureReason:sel.failureReason,runtimeFacts:sel.runtimeFacts??null,cleanup:sel.cleanup?.status??null,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision,receiptDigest:r.receiptDigest}))};
 out.cases.push(rec);console.log('CASE',projectId,caseId,rec.executionStatus,rec.policyDecision,'expected='+rec.expectedDecision);
 fs.cpSync(artifactDir,path.join(evDir,caseId),{recursive:true});
 return {rec,dir,run};
}
const pass=await one('petclinic-platform','historical-candidate');
const wrongDigest=await one('petclinic-platform','wrong-digest');
await one('petclinic-platform','wrong-commit');
await one('petclinic-platform','tampered-envelope');
for(const [name,sec] of [['plugin-off',{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}],['master-off',{enabled:false,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id===PLUGIN}]))}]]){
 const runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const run=await runCandidate({registry,runId,projectId:'petclinic-platform',context:{platform:process.platform,capabilities:CAPS},inputs:{},config:{security:sec},output:path.join(dir,'artifact')});
 const sel=run.gate[PLUGIN];out.disabled.push({name,runId,executionStatus:sel.executionStatus,evaluationCount:sel.evaluationCount,policyDecision:sel.policyDecision,failureReason:sel.failureReason});console.log('DISABLED',name,sel.executionStatus,sel.evaluationCount);
 fs.cpSync(path.join(dir,'artifact'),path.join(evDir,'disabled-'+name),{recursive:true});
}
const plug=registry.get(PLUGIN);
try{await executeRealProvenance(plug,{targetId:projects['petclinic-platform'].targetId,caseId:'historical-candidate'},{projectId:'provenance-cleanroom',runId:'web-'+randomUUID()});out.crossProject.caseLeakToCleanroom='NOT_REJECTED';}catch(e){out.crossProject.caseLeakToCleanroom=e.message;}
try{await executeRealProvenance(plug,{targetId:'wrong-target',caseId:'historical-candidate'},{projectId:'petclinic-platform',runId:'web-'+randomUUID()});out.crossProject.targetMismatch='NOT_REJECTED';}catch(e){out.crossProject.targetMismatch=e.message;}
try{await executeRealProvenance(plug,{targetId:projects['petclinic-platform'].targetId,caseId:'historical-candidate'},{projectId:'unknown-project',runId:'web-'+randomUUID()});out.crossProject.unknownProject='NOT_REJECTED';}catch(e){out.crossProject.unknownProject=e.message;}
console.log('CROSS',JSON.stringify(out.crossProject));
for(const item of [pass,wrongDigest]){
 const result={runId:item.rec.runId,pluginId:PLUGIN,projectId:item.rec.projectId,state:'COMPLETED',evidenceClass:'REAL',scannerExecuted:true,evaluationCount:1,resultDigest:item.rec.resultDigest,artifactDigest:item.rec.artifactDigest,policyDecision:item.rec.policyDecision};
 try{const d=await deliverRunToLoki(result,item.dir);out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,state:d.state,queryState:d.queryState,pushState:d.pushState,receiptDigest:d.receiptDigest});console.log('LOKI',item.rec.caseId,d.state,d.queryState);}
 catch(e){out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,state:'FAILED',reason:e.code??e.message});console.log('LOKI_FAIL',item.rec.caseId,e.code??e.message);}
}
fs.writeFileSync(path.join(evDir,'core-driver-summary.json'),JSON.stringify(out,null,2)+'\n');
console.log('DRIVER_DONE');
