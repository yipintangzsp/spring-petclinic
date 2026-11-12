import fs from 'node:fs';import path from 'node:path';import {randomUUID} from 'node:crypto';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';
import {realKubescapeRegistry} from '../../../infra/security/manager-v2/registry.mjs';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {kubescapeProjects,executeRealKubescape} from '../../../infra/security/manager-v2/kubescape-real.mjs';
import {deliverRunToLoki} from '../../../infra/security/manager-v2/view/loki-delivery.mjs';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const runsRoot=path.join(root,'.devsecops/kubescape-runs');fs.mkdirSync(runsRoot,{recursive:true,mode:0o755});
const evDir=path.join(root,'evidence/2026-11-13/kubescape-v2/raw');fs.mkdirSync(evDir,{recursive:true});
const registry=realKubescapeRegistry();
const projects=kubescapeProjects();
const out={cases:[],disabled:[],crossProject:{},loki:[]};
const CAPS={CLUSTER_ACCESS:{state:'AVAILABLE'},TRUSTED_EXECUTOR:{state:'AVAILABLE'}};
async function one(projectId,caseId,{deliver=false}={}){
 const cfg=projects[projectId],runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const artifactDir=path.join(dir,'artifact');
 const run=await runCandidate({registry,runId,projectId,context:{platform:process.platform,capabilities:CAPS},inputs:{kubescape:{targetId:cfg.targetId,caseId}},config:{security:{enabled:true,globalMode:'audit',securityLevel:'standard',profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='kubescape'}]))}},output:artifactDir});
 const sel=run.gate.kubescape;
 fs.mkdirSync(path.join(dir,'router'),{mode:0o700});
 const routed=routeResults({run,artifactDirectory:artifactDir,expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
 const rt=sel.runtimeFacts??{};
 const deploymentFindings=(rt.violatingFindings??[]).filter(f=>String(f.resourceId).includes('Deployment/smv2-violating'));
 const rec={runId,projectId,caseId,expectedDecision:cfg.cases[caseId].expectedDecision,gateStatus:rt.gateStatus??null,findings:rt.findings??null,failedControls:rt.failedControls??null,highRiskFindings:rt.highRiskFindings??null,auditDisposition:rt.auditDisposition??null,scans:(rt.scans??[]).map(s=>({scope:s.scope,framework:s.framework,resources:s.resources,failedControlCount:s.failedControlCount,complianceScore:s.complianceScore})),deploymentFindings,violatingCleanup:rt.violating??null,executionStatus:sel.executionStatus,policyDecision:sel.policyDecision,oldGateDecision:sel.oldGateDecision??null,evaluationCount:sel.evaluationCount,resultDigest:sel.resultDigest,artifactDigest:run.artifact.sealDigest,failureReason:sel.failureReason,cleanup:sel.cleanup?.status??null,router:routed.receipts.map(r=>({consumerId:r.consumerId,deliveryDecision:r.deliveryDecision,receiptDigest:r.receiptDigest}))};
 out.cases.push(rec);console.log('CASE',projectId,caseId,rec.executionStatus,rec.policyDecision,'gate='+rec.gateStatus,'findings='+rec.findings,'depFindings='+deploymentFindings.length);
 const caseEv=path.join(evDir,caseId+'-'+projectId);fs.mkdirSync(caseEv,{recursive:true});
 for(const f of ['kubescape.result.json','kubescape.runtime-facts.json','candidate-summary.json'])fs.copyFileSync(path.join(artifactDir,f),path.join(caseEv,f));
 if(deliver){
  const result={runId,pluginId:'kubescape',projectId,state:'COMPLETED',evidenceClass:'REAL',scannerExecuted:true,evaluationCount:1,resultDigest:rec.resultDigest,artifactDigest:rec.artifactDigest,policyDecision:rec.policyDecision};
  try{const d=await deliverRunToLoki(result,dir);out.loki.push({runId,caseId,state:d.state,queryState:d.queryState,pushState:d.pushState,receiptDigest:d.receiptDigest});console.log('LOKI',caseId,d.state,d.queryState);}
  catch(e){out.loki.push({runId,caseId,state:'FAILED',reason:e.code??e.message});console.log('LOKI_FAIL',caseId,e.code??e.message);}
 }
 return {rec,dir,run};
}
const main=await (async()=>{
 await one('kubescape-petclinic','cluster-audit',{deliver:true});
 await one('kubescape-petclinic','violating-workload',{deliver:true});
 await one('kubescape-cleanroom','posture-audit');
 for(const [name,sec] of [['plugin-off',{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'infra-k8s',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:false}]))}],['master-off',{enabled:false,globalMode:'audit',securityLevel:'standard',profile:'infra-k8s',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='kubescape'}]))}]]){
  const runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
  const run=await runCandidate({registry,runId,projectId:'kubescape-petclinic',context:{platform:process.platform,capabilities:CAPS},inputs:{},config:{security:sec},output:path.join(dir,'artifact')});
  const sel=run.gate.kubescape;out.disabled.push({name,runId,executionStatus:sel.executionStatus,evaluationCount:sel.evaluationCount,policyDecision:sel.policyDecision,failureReason:sel.failureReason});console.log('DISABLED',name,sel.executionStatus,sel.evaluationCount);
 }
 try{await executeRealKubescape(registry.get('kubescape'),{targetId:projects['kubescape-cleanroom'].targetId,caseId:'cluster-audit'},{projectId:'kubescape-petclinic',runId:'web-'+randomUUID()});out.crossProject.targetMismatch='NOT_REJECTED';}
 catch(e){out.crossProject.targetMismatch=e.message;}
 try{await executeRealKubescape(registry.get('kubescape'),{targetId:projects['kubescape-petclinic'].targetId,caseId:'posture-audit'},{projectId:'kubescape-petclinic',runId:'web-'+randomUUID()});out.crossProject.caseLeak='NOT_REJECTED';}
 catch(e){out.crossProject.caseLeak=e.message;}
 console.log('CROSS',JSON.stringify(out.crossProject));
 fs.writeFileSync(path.join(evDir,'core-driver-summary.json'),JSON.stringify(out,null,2)+'\n');
 console.log('DRIVER_DONE');
})();
