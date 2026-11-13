// Source-specific observed execution -> existing frozen adapter inputs.
// Does not call Policy or classify findings. Uncovered shapes stay unavailable.
import fs from 'node:fs';

export function executionPayload({sourceId,command,exitStatus,stdout,stderr,observation}){
  if(sourceId==='regression')return {schema:1,stage:'command',complete:true,command,
    execution:{status:exitStatus,signal:null,error:null},stdout,stderr};
  if(observation?.adapterPayload)return observation.adapterPayload;
  // Parent-stage runtime proof requires native facts. A shell exit cannot be
  // promoted to a complete wrapper observation, even when a frozen adapter
  // supports wrapper evidence for a different, explicitly scoped audit.
  // No status=success shortcut for unsupported native report projections.
  return {captureStatus:'SOURCE_SPECIFIC_OBSERVATIONS_UNAVAILABLE',sourceId,command,exitStatus,
    observedKinds:observation?.events?.map(e=>e.kind)??[],reason:'Cannot replace adapter-required raw observations with native success report'};
}
export function contractFor(sourceId){
  const required={
    gitleaks:['scanner exit','native report presence/parse/findings','original classifier inputs','prerequisite/isolation/cleanup','parent aggregation/report writes'],
    'semgrep-command-audit':['command-flow findings','high-confidence frozen Semgrep rules/native report','scanner execution/report/cleanup','source binding'],
    trivy:['original parent operation sequence','Harbor scan response and native report','DB/update and proxy-direct observations','reachability/fixability evidence','candidate/image/report binding'],
    zap:['target/report identity','confirmed High reproduction evidence','unconfirmed/lower-risk observations','container/network/report/cleanup outcomes'],
    sbom:['generator execution','original verifier extraction bytes','Maven SBOM bytes','source','mkdir/native/summary write observations'],
    sops:['prerequisites','targets.decrypt','targets.actual','targets.after','rbac','verifierRbac','reportWriteSucceeded'],
    'falco-baseline':['files','ds','sensorPods','node','diagnosticLog','samples.windowEndMs','samples.log','samples.workloads','health','reportWriteSucceeded'],
    'falco-final':['files','baseline','continuity','ds','sensorPods','node','diagnosticLog','samples.windowEndMs','samples.log','samples.workloads','health','reportWriteSucceeded'],
    kyverno:['configuration','rbac command observations','probes','live policy','owners','workloads','report writes'],
    kubescape:['lock','binary/artifact hashes','lease','read-only credential setup','scans','cleanup','report write'],
    cosign:['configuration','runtime','files','commands','registry','admissions','io'],
    defectdojo:['files','target','actual API request/response observations','credential presence'],
    sonarqube:['task','analysis id','authoritative projectStatus','conditions','binding'],
    provenance:['actual workflow cfg/params/environment/return','enabled branch only: git/steps/operations/DSSE/subject/builder binding'],
    'build-provenance':['actual workflow cfg/params/environment/return','enabled branch only: verification/inputIdentity/artifacts/architecture/candidate binding']
  };
  return {sourceId,adapterScope:required[sourceId]?'source-specific':'frozen wrapper/command',required:required[sourceId]??['actual command status','original module status','execution observations'],nativeSuccessSufficient:false};
}
