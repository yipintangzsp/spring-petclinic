// Engineering checkpoint verifier. No scanner, Policy evaluation or API call.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {fileURLToPath} from 'node:url';
import {EXPECTED_SOURCES} from '../../../infra/security/summary-v2/inventory.mjs';
import {validateResult,gateView} from '../../../infra/security/summary-v2/results.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export function verifyCheckpoint({root,checkpointPath,expectedSha256,readFile=p=>fs.readFileSync(p)}){
 const load=p=>{if(typeof p!=='string'||path.isAbsolute(p)||p.split('/').includes('..'))throw Error('CHECKPOINT_UNSAFE_PATH');return readFile(path.join(root,p));};
 const bytes=load(checkpointPath);if(sha(bytes)!==expectedSha256)throw Error('CHECKPOINT_BYTES_CHANGED');const c=JSON.parse(bytes);
 const require=(ok,msg)=>{if(!ok)throw Error('CHECKPOINT_'+msg);};
 require(c.kind==='AuthoritativeRuntimeCapabilityCheckpoint'&&c.classification==='RESUMABLE_ENGINEERING_CHECKPOINT_NOT_IMMUTABLE_PREAPPROVAL_ARTIFACT','KIND');
 require(c.expectedSourceCount===16&&c.acceptedWiredCount===14&&c.sources.length===16,'SOURCE_COUNT');
 require(new Set(c.sources.map(s=>s.sourceId)).size===16&&EXPECTED_SOURCES.every(id=>c.sources.some(s=>s.sourceId===id)),'CANONICAL_SET');
 require(!c.sameRun16Proven&&!c.completeRuntimeArtifactGenerated&&c.newRuntimePolicyEvaluations===0,'NO_COMPLETE_ARTIFACT');
 let checked=0;const reference=r=>{require(sha(load(r.path))===r.sha256,'REFERENCE_HASH:'+r.path);checked++;return JSON.parse(load(r.path));};
 const fileHash=(p,h)=>{require(sha(load(p))===h,'SOURCE_HASH:'+p);checked++;};
 for(const [p,h]of Object.entries(c.runtimeImplementationHashes))fileHash(p,h);
 for(const [p,h]of Object.entries(c.frozenGateHashes))fileHash(p,h);
 for(const r of [c.sourceManifest,c.collector,c.owner,c.authoritativePolicyOwner,c.projection,c.policyBaseline])fileHash(r.path,r.sha256);
 reference(c.guardReview);const resume=reference(c.resumeContract);require(resume.TRIVY_RESUME_ALLOWED===false&&!resume.B.approvalPresent&&resume.B.newApprovedGuard===null,'RESUME_NOT_AUTHORIZED');fileHash(resume.B.controlledPlan.path,resume.B.controlledPlan.sha256);
 const protection=reference(c.protectionDrift);reference(resume.protectionDriftReceipt);require(protection.unresolved&&protection.authoritativeCheckpointPromotionAllowed===false&&c.authoritativeAcceptance==='FAILED','PROTECTED_DRIFT_FAIL_CLOSED');
 let accepted=0;
 for(const s of c.sources){
  if(s.acceptance==='VERIFIED'){
   accepted++;require(s.sameRunAsThisCheckpoint===false&&s.evaluationCountThisReview===0,'NO_REBIND');
   const r=reference(s.receipts.result),cap=reference(s.receipts.capture),g=reference(s.receipts.gate);validateResult(r,s.binding);
   require(r.sourceId===s.sourceId&&r.resultDigest===s.resultDigest&&r.rawFactDigest===s.factDigest,'SOURCE_RECEIPT_IDENTITY');
   require(cap.evaluationCount===1&&cap.rawFactDigest===r.rawFactDigest&&cap.resultDigest===r.resultDigest,'CAPTURE_IDENTITY');
   require(g.resultDigest===r.resultDigest&&gateView(r,s.binding).resultDigest===g.resultDigest,'GATE_REUSE');
   require(s.observedPolicyStatus===r.result.status&&s.observedPolicyDecision===r.result.decision,'OBSERVED_BRANCH_PRESERVED');
   if(r.result.status==='SKIPPED')require(s.acceptedBranch==='OBSERVED_SKIPPED_BRANCH_ONLY'&&r.result.decision===null,'SKIPPED_NOT_ENABLED_PROOF');
   fileHash(s.originArchive.path,s.originArchive.sha256);
  }else{
   require(['trivy','defectdojo'].includes(s.sourceId)&&s.acceptance==='INCOMPLETE'&&s.policyResult===null&&s.blockerIsNotPolicyStatus,'BLOCKER_NOT_POLICY_RESULT');
   fileHash(s.origin.path,s.origin.sha256);const r=reference(s.engineeringReceipt);require(r.kind!=='ResolvedPolicyResult'&&r.kind!=='RuntimeSourceFacts','BLOCKER_KIND');
  }
 }
 require(accepted===14,'ACCEPTED_COUNT');reference(c.trivyBlockerReceipt);reference(c.dojoDependencyReceipt);reference(c.cosignVerifiedReceipt);
 require(c.productionJenkinsIdentity.latestBuild===270&&c.productionJenkinsIdentity.result==='SUCCESS','PRODUCTION_BUILD');
 for(const k of ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION'])require(c.currentRuntimeVerdicts[k]==='INCOMPLETE','OVERALL_VERDICT');
 require(c.currentRuntimeVerdicts.FINAL_WIRED_CAPABILITY==='14/16'&&c.currentRuntimeVerdicts.COSIGN_RUNTIME_FACT_CAPTURE==='VERIFIED','CAPABILITY_VERDICT');
 return {status:'FAILED',integrityStatus:'VERIFIED',blockedReasons:['UNEXPLAINED_PROXY_CONFIG_DRIFT'],resumeAllowed:false,kind:c.kind,sourceCount:16,acceptedWiredCount:accepted,blockedSources:c.blockedSources,checkedHashes:checked,policyEvaluations:0,newRuntimeArtifacts:0};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const base=path.dirname(fileURLToPath(import.meta.url)),root=path.resolve(base,'../../..'),anchor=JSON.parse(fs.readFileSync(path.join(base,'checkpoint-digest.json')));const result=verifyCheckpoint({root,checkpointPath:anchor.checkpointPath,expectedSha256:anchor.sha256});fs.writeFileSync(path.join(base,'checkpoint-integrity.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));if(result.status!=='VERIFIED')process.exitCode=2;
}
