import fs from 'node:fs';import path from 'node:path';import {randomUUID} from 'node:crypto';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';
import {realKyvernoRegistry} from '../../../infra/security/manager-v2/registry.mjs';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {kyvernoProjects,executeRealKyverno} from '../../../infra/security/manager-v2/kyverno-real.mjs';
import {deliverRunToLoki} from '../../../infra/security/manager-v2/view/loki-delivery.mjs';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const runsRoot=path.join(root,'.devsecops/kyverno-runs');fs.mkdirSync(runsRoot,{recursive:true,mode:0o755});
const evDir=path.join(root,'evidence/2026-11-12/kyverno-v2/raw');fs.mkdirSync(evDir,{recursive:true});
const registry=realKyvernoRegistry();
const projects=kyvernoProjects();
const out={cases:[],disabled:[],crossProject:{},loki:[]};
async function one(projectId,caseId){
 const cfg=projects[projectId],runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const artifactDir=path.join(dir,'artifact');
 const run=await runCandidate({registry,runId,projectId,context:{platform:process.platform,capabilities:{CLUSTER_ACCESS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{kyverno:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:'standard',profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='kyverno'}]))}},output:artifactDir});
 const sel=run.gate.kyverno;
 fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
 const routed=routeResults({run,artifactDirectory:artifactDir,expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
 const rec={runId,projectId,caseId,expectedAllowed:cfg.cases[caseId].expectedAllowed,allowed:sel.runtimeFacts?.allowed??null,executionStatus:sel.executionStatus,policyDecision:sel.policyDecision,evaluationCount:sel.evaluationCount,resultDigest:sel.resultDigest,artifactDigest:run.artifact.sealDigest,failureReason:sel.failureReason,realCreate:sel.runtimeFacts?.realCreate??null,cleanup:sel.cleanup?.status??null,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision,receiptDigest:r.receiptDigest}))};
 out.cases.push(rec);console.log('CASE',projectId,caseId,rec.executionStatus,rec.policyDecision,'allowed='+rec.allowed);
 return {rec,dir,run};
}
const main=await (async()=>{
 const signed=await one('kyverno-supply-chain','signed');
 await one('kyverno-supply-chain','unsigned');
 await one('kyverno-supply-chain','wrongkey');
 await one('kyverno-supply-chain','candidate');
 const compliant=await one('kyverno-workload','compliant');
 await one('kyverno-workload','host-access');
 // Disabled: plugin off (master on) and master off. Zero evaluation, zero SSH.
 for(const [name,sec] of [['plugin-off',{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'infra-k8s',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}],['master-off',{enabled:false,globalMode:'audit',securityLevel:'standard',profile:'infra-k8s',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='kyverno'}]))}]]){
  const runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
  const run=await runCandidate({registry,runId,projectId:'kyverno-supply-chain',context:{platform:process.platform,capabilities:{CLUSTER_ACCESS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}}},inputs:{},config:{security:sec},output:path.join(dir,'artifact')});
  const sel=run.gate.kyverno;out.disabled.push({name,runId,executionStatus:sel.executionStatus,evaluationCount:sel.evaluationCount,policyDecision:sel.policyDecision});console.log('DISABLED',name,sel.executionStatus,sel.evaluationCount);
 }
 // Cross-project: project A id with project B targetId must be rejected locally.
 try{await executeRealKyverno(registry.get('kyverno'),{targetId:projects['kyverno-workload'].targetId,caseId:'signed'},{projectId:'kyverno-supply-chain',runId:'web-'+randomUUID()});out.crossProject.mismatch='NOT_REJECTED';}
 catch(e){out.crossProject.mismatch=e.message;}
 try{await executeRealKyverno(registry.get('kyverno'),{targetId:projects['kyverno-supply-chain'].targetId,caseId:'compliant'},{projectId:'kyverno-supply-chain',runId:'web-'+randomUUID()});out.crossProject.caseLeak='NOT_REJECTED';}
 catch(e){out.crossProject.caseLeak=e.message;}
 console.log('CROSS',JSON.stringify(out.crossProject));
 // Fresh Loki delivery for the signed PASS run (query-verified by deliverRunToLoki).
 for(const item of [signed,compliant]){
  const result={runId:item.rec.runId,pluginId:'kyverno',projectId:item.rec.projectId,state:'COMPLETED',evidenceClass:'REAL',scannerExecuted:true,evaluationCount:1,resultDigest:item.rec.resultDigest,artifactDigest:item.rec.artifactDigest,policyDecision:item.rec.policyDecision};
  try{const d=await deliverRunToLoki(result,item.dir);out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,state:d.state,queryState:d.queryState,pushState:d.pushState,receiptDigest:d.receiptDigest});console.log('LOKI',item.rec.caseId,d.state,d.queryState);}
  catch(e){out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,state:'FAILED',reason:e.code??e.message});console.log('LOKI_FAIL',item.rec.caseId,e.code??e.message);}
 }
 fs.writeFileSync(path.join(evDir,'core-driver-summary.json'),JSON.stringify(out,null,2)+'\n');
 console.log('DRIVER_DONE');
})();
