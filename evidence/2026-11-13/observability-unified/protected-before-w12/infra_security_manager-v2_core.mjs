import {configuration,identity,keys} from './config.mjs';
import {registry as makeRegistry,capabilityCheck} from './registry.mjs';
import {executeArchive} from './archive.mjs';
import {executeRealTrivy} from './trivy-real.mjs';
import {executeRealSbom} from './sbom-real.mjs';
import {executeRealCosign} from './cosign-real.mjs';
import {executeRealSemgrep} from './semgrep-real.mjs';
import {executeRealGitleaks} from './gitleaks-real.mjs';
import {executeRealFalco} from './falco-real.mjs';
import {executeRealKyverno} from './kyverno-real.mjs';
import {executeRealSonar} from './sonar-real.mjs';
import {executeRealKubescape} from './kubescape-real.mjs';
import {executeRealZap} from './zap-real.mjs';
import {executeRealSops} from './sops-real.mjs';
import {executeRealProvenance} from './provenance-real.mjs';
import {executeRealBuildProvenance} from './build-provenance-real.mjs';
import {policyOwner,sealResult,verifyResult,artifactStore,verifyArtifact,legacyGateFields} from './result.mjs';
import {freeze,digest,fail} from '../summary-v2/codec.mjs';
export const MANAGER_VERSION='2.0.0-candidate.4';
const nonEvaluation=(p,base,status,reason)=>sealResult({...base,executionStatus:status,policyDecision:null,evaluationCount:0,policy:null,rawReportDigest:null,factDigest:null,evidenceRefs:[],failureReason:reason,completedAt:new Date().toISOString(),cleanup:null});
export async function runCandidate({config={},runId,projectId,context={platform:process.platform,capabilities:{}},inputs={},output,signal,registry=makeRegistry()}){
 identity(runId);identity(projectId);keys(inputs,registry.ids());
 const effective=configuration(config,projectId,registry.ids(),Object.fromEntries(registry.all().map(p=>[p.pluginId,p.enabled]))),owner=policyOwner(effective),store=artifactStore(output),results=[],gate={};
 store.put('effective-config.json',effective);
 for(const p of registry.all()){
  const base={schemaVersion:1,kind:'CandidatePluginResult',managerVersion:MANAGER_VERSION,securityEnabled:effective.enabled,effectiveProfile:effective.profile,globalMode:effective.globalMode,securityLevel:effective.securityLevel,runId,projectId,pluginId:p.pluginId,pluginVersion:p.pluginVersion,executionScope:'CANDIDATE_ONLY',startedAt:new Date().toISOString(),inputDigest:digest(inputs[p.pluginId]??null),configDigest:effective.configDigest,effectiveConfigDigest:effective.effectiveConfigDigest,contextDigest:digest(context),policyVersion:effective.policyVersion};
  let result;
  if(!effective.enabled||effective.globalMode==='off'||!effective.plugins[p.pluginId].enabled)result=nonEvaluation(p,base,'DISABLED',!effective.enabled?'MASTER_DISABLED':effective.globalMode==='off'?'MODE_OFF':'PLUGIN_DISABLED');
  else{
   const cap=capabilityCheck(p,context,effective.profile);
   if(cap.executionStatus!=='READY')result=nonEvaluation(p,base,cap.executionStatus,cap);
   else if(!inputs[p.pluginId])result=nonEvaluation(p,base,'NOT_CONFIGURED','PLUGIN_INPUT_MISSING');
   else{
    let execution;
    try{
     execution=p.runner==='falco-real'?await executeRealFalco(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='trivy-real'?await executeRealTrivy(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='sbom-real'?await executeRealSbom(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='cosign-real'?await executeRealCosign(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='semgrep-real'?await executeRealSemgrep(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='gitleaks-real'?await executeRealGitleaks(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='kyverno-real'?await executeRealKyverno(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='sonar-real'?await executeRealSonar(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='kubescape-real'?await executeRealKubescape(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='zap-real'?await executeRealZap(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='sops-real'?await executeRealSops(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='provenance-real'?await executeRealProvenance(p,inputs[p.pluginId],{signal,projectId,runId}):p.runner==='build-provenance-real'?await executeRealBuildProvenance(p,inputs[p.pluginId],{signal,projectId,runId}):await executeArchive(p,inputs[p.pluginId],{signal});
     if(execution.fact.component!==p.policyAdapter||execution.factDigest!==digest(execution.fact))fail('normalizer/adapter mismatch');
     store.putRaw(p.pluginId+'.raw.json',execution.rawReportBytesUtf8);
     const policy=await owner.evaluateOnce(p.pluginId,execution.fact);
     if(execution.runtimeFacts){store.put(p.pluginId+'.runtime-facts.json',execution.runtimeFacts);store.put(p.pluginId+'.facts.json',execution.fact);if(execution.oldDecision!==undefined&&policy.evaluation.status!=='POLICY_ERROR'&&policy.evaluation.decision!==execution.oldDecision)fail('real old Gate and Policy differ');}
     result=sealResult({...base,executionScope:execution.executionScope,executionStatus:policy.evaluation.status==='POLICY_ERROR'?'POLICY_ERROR':policy.evaluation.decision===null?'NOT_CONFIGURED':'COMPLETED',policyDecision:policy.evaluation.decision,evaluationCount:policy.evaluationCount,policy,rawReportDigest:execution.rawReportDigest,factDigest:execution.factDigest,evidenceRefs:execution.evidenceRefs,failureReason:policy.evaluation.status==='POLICY_ERROR'?policy.evaluation.error:policy.evaluation.decision===null?'POLICY_EVIDENCE_INCOMPLETE':null,completedAt:new Date().toISOString(),cleanup:execution.cleanup,...legacyGateFields(execution)});
    }catch(e){
     const notConfigured=e.message==='COSIGN_TOOL_NOT_CONFIGURED',policyError=String(e.message).startsWith('POLICY_ERROR:'),unsupported=['GITLEAKS_UNSUPPORTED_IDENTITY','SEMGREP_UNSUPPORTED_IDENTITY','SEMGREP_UNSUPPORTED_SOURCE','COSIGN_UNSUPPORTED_IDENTITY','FALCO_UNSUPPORTED_IDENTITY'].includes(e.message);
     if(e.candidateEvidence){const {rawReportBytesUtf8,...evidence}=e.candidateEvidence;store.put(p.pluginId+'.execution-error.json',evidence);if(rawReportBytesUtf8)store.putRaw(p.pluginId+'.raw.json',rawReportBytesUtf8);execution={rawReportDigest:e.candidateEvidence.rawReportDigest};}
     const safeError=/^RUNNER_(TIMEOUT|CANCELLED|ERROR|EXIT_ERROR|CLEANUP_FAILED|SCANNER_ERROR|TOOL_VERSION_ERROR|REPORT_ERROR|UNSAFE_REPORT|OUTPUT_LIMIT)$/.test(e.message)?e.message:'RUNNER_OR_COLLECTION_ERROR';
     result=sealResult({...base,executionStatus:policyError?'POLICY_ERROR':notConfigured?'NOT_CONFIGURED':unsupported?'UNSUPPORTED':'ERROR',policyDecision:null,evaluationCount:owner.counts()[p.pluginId]??0,policy:null,rawReportDigest:execution?.rawReportDigest??null,factDigest:execution?.factDigest??null,evidenceRefs:execution?.evidenceRefs??[],failureReason:policyError?e.message:notConfigured?e.message:unsupported?e.message:safeError,completedAt:new Date().toISOString(),cleanup:execution?.cleanup??{status:safeError==='RUNNER_CLEANUP_FAILED'?'INCOMPLETE':'JOINED_OR_NOT_STARTED'}});
    }
   }
  }
  verifyResult(result);store.put(p.pluginId+'.result.json',result);results.push(result);gate[p.pluginId]=result;
 }
 const blockers=results.filter(r=>!['COMPLETED','DISABLED'].includes(r.executionStatus)||r.policyDecision==='FAIL').map(r=>({pluginId:r.pluginId,executionStatus:r.executionStatus,policyDecision:r.policyDecision,reason:r.failureReason}));
 const allDisabled=results.every(r=>r.executionStatus==='DISABLED');
 const operational=results.some(r=>['ERROR','POLICY_ERROR'].includes(r.executionStatus));
 const incomplete=results.some(r=>!['COMPLETED','DISABLED'].includes(r.executionStatus));
 const overallStatus=allDisabled?'DISABLED':results.some(r=>r.executionStatus==='POLICY_ERROR')?'POLICY_ERROR':operational?'ERROR':results.some(r=>r.policyDecision==='FAIL')?'FAIL':incomplete?'INCOMPLETE':results.some(r=>r.policyDecision==='WARN')?'WARN':'PASS';
 const summary=freeze({schemaVersion:1,kind:'SecuritySummaryCandidate',managerVersion:MANAGER_VERSION,runId,validationRunId:runId,projectId,profile:effective.profile,effectiveProfile:effective.profile,securityEnabled:effective.enabled,globalMode:effective.globalMode,securityLevel:effective.securityLevel,policyVersion:effective.policyVersion,policySource:effective.policySource,effectivePolicy:effective.effectivePolicy,appliedOverrides:effective.appliedOverrides,configurationOrigins:effective.configurationOrigins,effectiveConfigDigest:effective.effectiveConfigDigest,contextDigest:digest(context),capabilityEvidenceClass:results.some(r=>r.runtimeFacts)?'REAL_TOOL_AND_ROOT_OWNED_FIXTURE_APPROVAL_PLUS_DECLARED_HINTS':'CALLER_DECLARED_OFFLINE_CONTEXT',pluginResults:results,overallStatus,overallDecision:overallStatus,
  evidenceRefs:results.flatMap(r=>r.evidenceRefs),blockers,candidateBuildAllowed:!operational&&(effective.globalMode!=='enforce'||!incomplete&&!results.some(r=>r.policyDecision==='FAIL')),promotion:{status:'BLOCKED',reason:'CANDIDATE_ONLY_NOT_PRODUCTION_GATE_EVIDENCE'},productionEvidence:false,releaseCount:0,rolloutCount:0});
 store.put('candidate-summary.json',summary);const artifact=store.finish();verifyArtifact(output,artifact.sealDigest);
 return freeze({summary,gate,artifact,policyEvaluationCounts:owner.counts()});
}
