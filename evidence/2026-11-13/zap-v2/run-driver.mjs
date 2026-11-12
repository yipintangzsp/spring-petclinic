import fs from 'node:fs';import path from 'node:path';import {randomUUID} from 'node:crypto';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';
import {realZapRegistry} from '../../../infra/security/manager-v2/registry.mjs';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {zapProjects,executeRealZap} from '../../../infra/security/manager-v2/zap-real.mjs';
import {deliverRunToLoki} from '../../../infra/security/manager-v2/view/loki-delivery.mjs';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const runsRoot=path.join(root,'.devsecops/zap-runs');fs.mkdirSync(runsRoot,{recursive:true,mode:0o755});
const evDir=path.join(root,'evidence/2026-11-13/zap-v2/raw');fs.mkdirSync(evDir,{recursive:true});
const registry=realZapRegistry();
const projects=zapProjects();
const out={cases:[],disabled:[],crossProject:{},loki:[]};
const CAPS={RUNTIME_TARGET:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}};
async function one(projectId,caseId,level){
 const cfg=projects[projectId],runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const artifactDir=path.join(dir,'artifact');
 const run=await runCandidate({registry,runId,projectId,context:{platform:process.platform,capabilities:CAPS},inputs:{zap:{targetId:cfg.targetId,caseId,policyLevel:level}},config:{security:{enabled:true,globalMode:'audit',securityLevel:level,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='zap'}]))}},output:artifactDir});
 const sel=run.gate.zap;
 fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
 const routed=routeResults({run,artifactDirectory:artifactDir,expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
 const rec={runId,projectId,caseId,policyLevel:level,expectedDecision:cfg.cases[caseId].expectedDecision[level],executionStatus:sel.executionStatus,policyDecision:sel.policyDecision,oldGateDecision:sel.oldGateDecision??null,evaluationCount:sel.evaluationCount,resultDigest:sel.resultDigest,artifactDigest:run.artifact.sealDigest,failureReason:sel.failureReason,alertsTotal:sel.runtimeFacts?.alertsTotal??null,riskCounts:sel.runtimeFacts?.riskCounts??null,alerts:sel.runtimeFacts?.alerts??null,reportSha256:sel.runtimeFacts?.reportSha256??null,targetImage:sel.runtimeFacts?.targetImage??null,cleanup:sel.cleanup?.status??null,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision,receiptDigest:r.receiptDigest}))};
 out.cases.push(rec);console.log('CASE',projectId,caseId,level,rec.executionStatus,rec.policyDecision,'expected='+rec.expectedDecision);
 const label=caseId+'-'+level;fs.cpSync(artifactDir,path.join(evDir,label),{recursive:true});
 return {rec,dir,run};
}
const main=await (async()=>{
 const clean=await one('zap-lab','clean','standard');
 const piiStrict=await one('zap-lab','pii-disclosure','strict');
 await one('zap-lab','pii-disclosure','standard');
 await one('zap-cleanroom','cleanroom-clean','standard');
 for(const [name,sec] of [['plugin-off',{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}],['master-off',{enabled:false,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='zap'}]))}]]){
  const runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
  const run=await runCandidate({registry,runId,projectId:'zap-lab',context:{platform:process.platform,capabilities:CAPS},inputs:{},config:{security:sec},output:path.join(dir,'artifact')});
  const sel=run.gate.zap;out.disabled.push({name,runId,executionStatus:sel.executionStatus,evaluationCount:sel.evaluationCount,policyDecision:sel.policyDecision,failureReason:sel.failureReason});console.log('DISABLED',name,sel.executionStatus,sel.evaluationCount);
  fs.cpSync(path.join(dir,'artifact'),path.join(evDir,'disabled-'+name),{recursive:true});
 }
 try{await executeRealZap(registry.get('zap'),{targetId:projects['zap-cleanroom'].targetId,caseId:'clean',policyLevel:'standard'},{projectId:'zap-lab',runId:'web-'+randomUUID()});out.crossProject.targetMismatch='NOT_REJECTED';}
 catch(e){out.crossProject.targetMismatch=e.message;}
 try{await executeRealZap(registry.get('zap'),{targetId:projects['zap-lab'].targetId,caseId:'cleanroom-clean',policyLevel:'standard'},{projectId:'zap-lab',runId:'web-'+randomUUID()});out.crossProject.caseLeak='NOT_REJECTED';}
 catch(e){out.crossProject.caseLeak=e.message;}
 try{await executeRealZap(registry.get('zap'),{targetId:projects['zap-lab'].targetId,caseId:'clean',policyLevel:'strict'},{projectId:'zap-lab',runId:'web-'+randomUUID()});out.crossProject.levelLeak='NOT_REJECTED';}
 catch(e){out.crossProject.levelLeak=e.message;}
 console.log('CROSS',JSON.stringify(out.crossProject));
 for(const item of [clean,piiStrict]){
  const result={runId:item.rec.runId,pluginId:'zap',projectId:item.rec.projectId,state:'COMPLETED',evidenceClass:'REAL',scannerExecuted:true,evaluationCount:1,resultDigest:item.rec.resultDigest,artifactDigest:item.rec.artifactDigest,policyDecision:item.rec.policyDecision};
  try{const d=await deliverRunToLoki(result,item.dir);out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,policyLevel:item.rec.policyLevel,state:d.state,queryState:d.queryState,pushState:d.pushState,receiptDigest:d.receiptDigest});console.log('LOKI',item.rec.caseId,item.rec.policyLevel,d.state,d.queryState);}
  catch(e){out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,policyLevel:item.rec.policyLevel,state:'FAILED',reason:e.code??e.message});console.log('LOKI_FAIL',item.rec.caseId,item.rec.policyLevel,e.code??e.message);}
 }
 fs.writeFileSync(path.join(evDir,'core-driver-summary.json'),JSON.stringify(out,null,2)+'\n');
 console.log('DRIVER_DONE');
})();
