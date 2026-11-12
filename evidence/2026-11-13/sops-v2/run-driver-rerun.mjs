import fs from 'node:fs';import path from 'node:path';import {randomUUID} from 'node:crypto';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';
import {realSopsRegistry} from '../../../infra/security/manager-v2/registry.mjs';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {sopsProjects,executeRealSops} from '../../../infra/security/manager-v2/sops-real.mjs';
import {deliverRunToLoki} from '../../../infra/security/manager-v2/view/loki-delivery.mjs';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const runsRoot=path.join(root,'.devsecops/sops-runs');fs.mkdirSync(runsRoot,{recursive:true,mode:0o755});
const evDir=path.join(root,'evidence/2026-11-13/sops-v2/raw-rerun');fs.mkdirSync(evDir,{recursive:true});
const registry=realSopsRegistry();
const projects=sopsProjects();
const out={cases:[],disabled:[],crossProject:{},loki:[]};
const CAPS={CREDENTIALS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}};
async function one(projectId,caseId,level='standard'){
 const cfg=projects[projectId],runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const artifactDir=path.join(dir,'artifact');
 const run=await runCandidate({registry,runId,projectId,context:{platform:process.platform,capabilities:CAPS},inputs:{sops:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:level,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='sops'}]))}},output:artifactDir});
 const sel=run.gate.sops;
 fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
 const routed=routeResults({run,artifactDirectory:artifactDir,expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
 const rec={runId,projectId,caseId,policyLevel:level,expectedDecision:cfg.cases[caseId].expectedDecision[level],executionStatus:sel.executionStatus,policyDecision:sel.policyDecision,oldGateDecision:sel.oldGateDecision??null,evaluationCount:sel.evaluationCount,resultDigest:sel.resultDigest,artifactDigest:run.artifact.sealDigest,failureReason:sel.failureReason,cleanup:sel.cleanup?.status??null,storeModel:sel.runtimeFacts?.storeModel??null,rbacModel:sel.runtimeFacts?.rbacModel??null,cipherFacts:sel.runtimeFacts?.cipherFacts??null,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision,receiptDigest:r.receiptDigest}))};
 out.cases.push(rec);console.log('CASE',projectId,caseId,rec.executionStatus,rec.policyDecision,'expected='+rec.expectedDecision);
 fs.cpSync(artifactDir,path.join(evDir,projectId+'-'+caseId),{recursive:true});
 return {rec,dir,run};
}
const main=await (async()=>{
 const compliant=await one('sops-lab','compliant');
 const tampered=await one('sops-lab','tampered-ciphertext');
 await one('sops-lab','wrong-key');
 await one('sops-lab','plaintext-masquerade');
 await one('sops-lab','data-drift');
 await one('sops-cleanroom','compliant');
 for(const [name,sec] of [['plugin-off',{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}],['master-off',{enabled:false,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='sops'}]))}]]){
  const runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
  const run=await runCandidate({registry,runId,projectId:'sops-lab',context:{platform:process.platform,capabilities:CAPS},inputs:{},config:{security:sec},output:path.join(dir,'artifact')});
  const sel=run.gate.sops;out.disabled.push({name,runId,executionStatus:sel.executionStatus,evaluationCount:sel.evaluationCount,policyDecision:sel.policyDecision,failureReason:sel.failureReason});console.log('DISABLED',name,sel.executionStatus,sel.evaluationCount);
  fs.cpSync(path.join(dir,'artifact'),path.join(evDir,'disabled-'+name),{recursive:true});
 }
 try{await executeRealSops(registry.get('sops'),{targetId:projects['sops-cleanroom'].targetId,caseId:'compliant'},{projectId:'sops-lab',runId:'web-'+randomUUID()});out.crossProject.targetMismatch='NOT_REJECTED';}
 catch(e){out.crossProject.targetMismatch=e.message;}
 try{await executeRealSops(registry.get('sops'),{targetId:projects['sops-lab'].targetId,caseId:'compliant'},{projectId:'sops-cleanroom',runId:'web-'+randomUUID()});out.crossProject.cleanroomIntoLabTarget='NOT_REJECTED';}
 catch(e){out.crossProject.cleanroomIntoLabTarget=e.message;}
 try{await executeRealSops(registry.get('sops'),{targetId:projects['sops-lab'].targetId,caseId:'wrong-key'},{projectId:'sops-cleanroom',runId:'web-'+randomUUID()});out.crossProject.caseLeak='NOT_REJECTED';}
 catch(e){out.crossProject.caseLeak=e.message;}
 console.log('CROSS',JSON.stringify(out.crossProject));
 for(const item of [compliant,tampered]){
  const result={runId:item.rec.runId,pluginId:'sops',projectId:item.rec.projectId,state:'COMPLETED',evidenceClass:'REAL',scannerExecuted:true,evaluationCount:1,resultDigest:item.rec.resultDigest,artifactDigest:item.rec.artifactDigest,policyDecision:item.rec.policyDecision};
  try{const d=await deliverRunToLoki(result,item.dir);out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,state:d.state,queryState:d.queryState,pushState:d.pushState,receiptDigest:d.receiptDigest});console.log('LOKI',item.rec.caseId,d.state,d.queryState);}
  catch(e){out.loki.push({runId:item.rec.runId,caseId:item.rec.caseId,state:'FAILED',reason:e.code??e.message});console.log('LOKI_FAIL',item.rec.caseId,e.code??e.message);}
 }
 fs.writeFileSync(path.join(evDir,'core-driver-summary-rerun.json'),JSON.stringify(out,null,2)+'\n');
 console.log('DRIVER_DONE');
})();
