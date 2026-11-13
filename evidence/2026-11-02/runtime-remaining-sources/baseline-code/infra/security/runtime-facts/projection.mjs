// Source-specific observed execution -> existing frozen adapter inputs.
// Does not call Policy or classify findings. Uncovered shapes stay unavailable.
import fs from 'node:fs';

export function executionPayload({sourceId,command,exitStatus,stdout,stderr,observation}){
  if(sourceId==='regression')return {schema:1,stage:'command',complete:true,command,
    execution:{status:exitStatus,signal:null,error:null},stdout,stderr};
  if(observation?.adapterPayload)return observation.adapterPayload;
  // Preserve a real wrapper observation only for adapters whose frozen contract
  // explicitly supports wrapper scope. Never present it as child CLI coverage.
  if(['gitleaks','semgrep-command-audit','trivy','zap'].includes(sourceId))return {
    schema:1,stage:'wrapper',complete:true,execution:{failed:exitStatus!==0},
    module:{status:exitStatus===0?'success':'failed'},observations:[{type:'actual-module-command',command,exitStatus}]
  };
  if(sourceId==='sbom')return {stage:'workflow',complete:true,files:{},io:{},execution:{failed:exitStatus!==0},
    moduleStatus:exitStatus===0?'success':'failed',module:{status:exitStatus===0?'success':'failed'},observations:[{command,exitStatus}]};
  // No status=success shortcut for unsupported native report projections.
  return {captureStatus:'SOURCE_SPECIFIC_OBSERVATIONS_UNAVAILABLE',sourceId,command,exitStatus,
    observedKinds:observation?.events?.map(e=>e.kind)??[],reason:'Cannot replace adapter-required raw observations with native success report'};
}
export function contractFor(sourceId){
  const required={
    sops:['prerequisites','targets.decrypt','targets.actual','targets.after','rbac','verifierRbac','reportWriteSucceeded'],
    'falco-baseline':['files','ds','sensorPods','node','diagnosticLog','samples.windowEndMs','samples.log','samples.workloads','health','reportWriteSucceeded'],
    'falco-final':['files','baseline','continuity','ds','sensorPods','node','diagnosticLog','samples.windowEndMs','samples.log','samples.workloads','health','reportWriteSucceeded'],
    kyverno:['configuration','rbac command observations','probes','live policy','owners','workloads','report writes'],
    kubescape:['lock','binary/artifact hashes','lease','read-only credential setup','scans','cleanup','report write'],
    cosign:['configuration','runtime','files','commands','registry','admissions','io'],
    defectdojo:['files','target','actual API request/response observations','credential presence'],
    sonarqube:['task','analysis id','authoritative projectStatus','conditions','binding'],
    provenance:['workflow cfg/params/environment','git','steps','operations'],
    'build-provenance':['verification execution','inputIdentity','artifacts','observations']
  };
  return {sourceId,adapterScope:required[sourceId]?'source-specific':'frozen wrapper/command',required:required[sourceId]??['actual command status','original module status','execution observations'],nativeSuccessSufficient:false};
}
