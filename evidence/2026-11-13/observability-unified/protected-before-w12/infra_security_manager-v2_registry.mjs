import {freeze,fail,object} from '../summary-v2/codec.mjs';
import {PROFILES,identity,keys} from './config.mjs';
export const CAPABILITIES=Object.freeze(['SOURCE_DIR','IMAGE_REF','CANDIDATE_DIGEST','SBOM_FILE','MANIFEST_DIR','RUNTIME_TARGET','CLUSTER_ACCESS','REGISTRY_ACCESS','CREDENTIALS','BUILD_METADATA','PROVENANCE_METADATA','SECURITY_REPORTS','DEFECTDOJO_API','FRESH_DB','PROVEN_DISK_BUDGET','TRUSTED_EXECUTOR','GITLEAKS_TOOL','TRUSTED_VALIDATION_WORKSPACE','SEMGREP_BINARY','SEMGREP_RULESET','OUTPUT_DIR','POLICY_VERSION','COSIGN_BINARY','COSIGN_VERSION','OFFLINE_SIGNED_OBJECT','TRUSTED_VERIFICATION_IDENTITY','SIGNATURE_SOURCE','VALIDATION_OUTPUT_DIR']);
const make=(id,required,component=id,replay=false)=>({pluginId:id,pluginVersion:'2.0.0-candidate.1',displayName:id,enabled:true,executionMode:replay?'OFFLINE_REPLAY':'PREFLIGHT_ONLY',requiredCapabilities:required,optionalCapabilities:[],supportedProfiles:PROFILES,inputContract:'ApprovedArchive/v1',outputContract:'CandidatePluginResult/v1',runner:replay?'archive-worker':'blocked',normalizer:'preserve-raw/v1',policyAdapter:component,timeout:2000,cleanupPolicy:'TERMINATE_AND_JOIN_WORKER'});
export const BUILTINS=freeze([
 make('gitleaks',['SECURITY_REPORTS'],'gitleaks',true),make('semgrep',['SECURITY_REPORTS'],'semgrep-command-audit',true),make('cosign',['SECURITY_REPORTS'],'cosign',true),
 make('trivy',['FRESH_DB','PROVEN_DISK_BUDGET','TRUSTED_EXECUTOR']),
 make('sonarqube',['RUNTIME_TARGET','CREDENTIALS']),make('sbom',['SBOM_FILE']),make('kubescape',['MANIFEST_DIR']),make('zap',['RUNTIME_TARGET']),
 make('provenance',['PROVENANCE_METADATA']),make('build-provenance',['BUILD_METADATA']),make('sops',['CREDENTIALS']),make('kyverno',['CLUSTER_ACCESS']),make('falco',['RUNTIME_TARGET'])
]);
// Code-owned definitions only. JSON configuration cannot supply runner functions/code.
export function registry(definitions=BUILTINS){
 if(!Array.isArray(definitions))fail('registry definitions');const map=new Map();
 for(const p of definitions){
  keys(p,Object.keys(BUILTINS[0]));identity(p.pluginId);
  if(map.has(p.pluginId))fail('duplicate plugin ID');
  const realSemgrep=p.pluginId==='semgrep'&&p.runner==='semgrep-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='semgrep-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='semgrep';
  const realCosign=p.pluginId==='cosign'&&p.runner==='cosign-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='cosign-blob/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='cosign';
  const realSbom=p.pluginId==='sbom'&&p.runner==='sbom-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='cyclonedx-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP';
  const realTrivy=p.pluginId==='trivy'&&p.runner==='trivy-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='trivy-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP';
  const realKyverno=p.pluginId==='kyverno'&&p.runner==='kyverno-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='kyverno-admission/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='kyverno-admission';
  const realFalco=p.pluginId==='falco'&&p.runner==='falco-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='falco-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='falco-final';
  const realKubescape=p.pluginId==='kubescape'&&p.runner==='kubescape-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='kubescape-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='kubescape';
  const realSonar=p.pluginId==='sonarqube'&&p.runner==='sonar-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='sonar-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='sonarqube';
  const realZap=p.pluginId==='zap'&&p.runner==='zap-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='zap-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='zap';
  const realSops=p.pluginId==='sops'&&p.runner==='sops-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='sops-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='sops';
  const realProvenance=p.pluginId==='provenance'&&p.runner==='provenance-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='provenance-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='provenance';
  const realBuildProvenance=p.pluginId==='build-provenance'&&p.runner==='build-provenance-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='build-provenance-native/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP'&&p.policyAdapter==='build-provenance';
  const real=realFalco||realSonar||realKubescape||realZap||realSops||realProvenance||realBuildProvenance||realKyverno||realTrivy||realSbom||realCosign||realSemgrep||p.pluginId==='gitleaks'&&p.runner==='gitleaks-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='gitleaks-dir/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP';
  if(typeof p.enabled!=='boolean'||!Number.isSafeInteger(p.timeout)||p.timeout<1||p.timeout>(realTrivy?210000:realSonar?180000:realKubescape?1500000:realZap?240000:realSops?120000:30000)||!real&&(!['archive-worker','blocked'].includes(p.runner)||!['OFFLINE_REPLAY','PREFLIGHT_ONLY'].includes(p.executionMode)||p.normalizer!=='preserve-raw/v1'||p.cleanupPolicy!=='TERMINATE_AND_JOIN_WORKER'))fail('untrusted runner contract');
  if(![p.requiredCapabilities,p.optionalCapabilities].every(x=>Array.isArray(x)&&x.every(c=>CAPABILITIES.includes(c)))||!Array.isArray(p.supportedProfiles)||!p.supportedProfiles.every(x=>PROFILES.includes(x)))fail('registry capability/profile');
  if(!['pluginVersion','displayName','inputContract','outputContract','policyAdapter'].every(k=>typeof p[k]==='string'&&p[k]))fail('registry identity/contract');
  map.set(p.pluginId,freeze(structuredClone(p)));
 }
 return Object.freeze({ids:()=>[...map.keys()].sort(),get:id=>{if(!map.has(id))fail('unknown plugin ID');return map.get(id);},all:()=>[...map.values()].sort((a,b)=>a.pluginId.localeCompare(b.pluginId))});
}
export function realGitleaksRegistry(){return registry(BUILTINS.map(p=>p.pluginId==='gitleaks'?{...p,pluginVersion:'2.0.0-candidate.2',enabled:false,executionMode:'REAL_VALIDATION',runner:'gitleaks-real',normalizer:'gitleaks-dir/v1',requiredCapabilities:['SOURCE_DIR','GITLEAKS_TOOL','TRUSTED_VALIDATION_WORKSPACE'],timeout:10000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}
export function capabilityCheck(plugin,context,profile){
 keys(context,['platform','capabilities']);const caps=context.capabilities??{};keys(caps,CAPABILITIES);
 for(const c of Object.values(caps)){keys(c,['state','reason']);if(!['AVAILABLE','UNAVAILABLE','NOT_CONFIGURED'].includes(c.state)||c.reason!==undefined&&typeof c.reason!=='string')fail('capability state');}
 if(!['linux','darwin','win32'].includes(context.platform))fail('platform unknown');
 if(!plugin.supportedProfiles.includes(profile))return {executionStatus:'SKIPPED',reason:'PROFILE_NOT_SUPPORTED',missing:[]};
 if(!['linux','darwin'].includes(context.platform))return {executionStatus:'UNSUPPORTED',reason:'PLATFORM_UNSUPPORTED',missing:[]};
 if(['gitleaks-real','semgrep-real','cosign-real','falco-real'].includes(plugin.runner)&&context.platform!=='linux')return {executionStatus:'UNSUPPORTED',reason:'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY',missing:[]};
 const missing=plugin.requiredCapabilities.filter(k=>caps[k]?.state!=='AVAILABLE');
 if(missing.length)return {executionStatus:missing.some(k=>caps[k]?.state==='UNAVAILABLE')?'UNSUPPORTED':'NOT_CONFIGURED',reason:'CAPABILITY_BLOCKED',missing};
 if(plugin.runner==='blocked')return {executionStatus:'NOT_CONFIGURED',reason:plugin.pluginId==='trivy'?'TRIVY_REAL_EXECUTION_PROHIBITED':'LIVE_RUNNER_NOT_IMPLEMENTED',missing:[]};
 return {executionStatus:'READY',reason:null,missing:[]};
}

// Explicit code-owned opt-in. Replay/default registry and existing Gitleaks API stay unchanged.
export function realPluginsRegistry({gitleaks=true,semgrep=true}={}){
 return registry((gitleaks?realGitleaksRegistry():registry()).all().map(p=>semgrep&&p.pluginId==='semgrep'?{...p,pluginVersion:'2.0.0-candidate.3',enabled:false,executionMode:'REAL_VALIDATION',runner:'semgrep-real',normalizer:'semgrep-native/v1',policyAdapter:'semgrep',requiredCapabilities:['SOURCE_DIR','SEMGREP_BINARY','SEMGREP_RULESET','OUTPUT_DIR','POLICY_VERSION','TRUSTED_VALIDATION_WORKSPACE'],timeout:30000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));
}

// Additive third native plugin; existing two-plugin registry remains byte-compatible in behavior.
export function realThreePluginsRegistry(){return registry(realPluginsRegistry().all().map(p=>p.pluginId==='cosign'?{...p,pluginVersion:'2.0.0-candidate.4',enabled:false,executionMode:'REAL_VALIDATION',runner:'cosign-real',normalizer:'cosign-blob/v1',requiredCapabilities:['COSIGN_BINARY','COSIGN_VERSION','OFFLINE_SIGNED_OBJECT','TRUSTED_VERIFICATION_IDENTITY','SIGNATURE_SOURCE','POLICY_VERSION','VALIDATION_OUTPUT_DIR','TRUSTED_VALIDATION_WORKSPACE'],timeout:10000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

export function realManagedRegistry(){return registry(realThreePluginsRegistry().all().map(p=>p.pluginId==='trivy'?{...p,runner:'trivy-real',executionMode:'REAL_VALIDATION',normalizer:'trivy-native/v1',pluginVersion:'2.0.0-candidate.6',requiredCapabilities:['IMAGE_REF','FRESH_DB','TRUSTED_EXECUTOR'],timeout:210000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p.pluginId==='sbom'?{...p,runner:'sbom-real',executionMode:'REAL_VALIDATION',normalizer:'cyclonedx-native/v1',pluginVersion:'2.0.0-candidate.5',requiredCapabilities:['SBOM_FILE'],timeout:30000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Additive sixth native plugin; existing managed registry remains unchanged.
// Falco's frozen Policy adapter is the falco-final stage (falco-parent.mjs):
// the runner supplies real sensor observations, never a decision.
export function realKyvernoRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='kyverno'?{...p,runner:'kyverno-real',executionMode:'REAL_VALIDATION',normalizer:'kyverno-admission/v1',policyAdapter:'kyverno-admission',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['CLUSTER_ACCESS','TRUSTED_EXECUTOR'],timeout:30000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}
export function realFalcoRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='falco'?{...p,runner:'falco-real',executionMode:'REAL_VALIDATION',normalizer:'falco-native/v1',policyAdapter:'falco-final',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['RUNTIME_TARGET'],timeout:30000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Additive seventh native plugin; existing managed registry remains unchanged.
// SonarQube's frozen Policy adapter consumes the server Quality Gate as
// authoritative (infra/security/policy/sonar-evidence.mjs): the runner
// supplies real task/gate observations, never a decision.
export function realSonarRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='sonarqube'?{...p,runner:'sonar-real',executionMode:'REAL_VALIDATION',normalizer:'sonar-native/v1',policyAdapter:'sonarqube',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['RUNTIME_TARGET','CREDENTIALS','TRUSTED_EXECUTOR'],timeout:180000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Additive eighth native plugin; existing managed registry remains unchanged.
// Kubescape's frozen Policy adapter is the AUDIT gate in
// infra/security/policy/kubescape-parent.mjs: the runner supplies the real
// governance execution observations, never a decision.
export function realKubescapeRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='kubescape'?{...p,runner:'kubescape-real',executionMode:'REAL_VALIDATION',normalizer:'kubescape-native/v1',policyAdapter:'kubescape',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['CLUSTER_ACCESS','TRUSTED_EXECUTOR'],timeout:1500000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Additive native plugin; existing managed registry remains unchanged.
// ZAP's frozen Policy adapter consumes the native report through the
// existing classifyZap classifier (infra/security/zap-policy.mjs): the
// runner supplies real passive-scan observations, never a decision.
export function realZapRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='zap'?{...p,runner:'zap-real',executionMode:'REAL_VALIDATION',normalizer:'zap-native/v1',policyAdapter:'zap',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['RUNTIME_TARGET','TRUSTED_EXECUTOR'],timeout:240000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Additive native plugins; existing managed registry remains unchanged.
// Provenance's frozen Policy adapter is provenanceParent: the runner
// supplies genuine replay observations whose cosign verify-attestation
// command carries the real archived DSSE envelope; the adapter's own
// verifyEnvelope + validate perform the verification.
export function realProvenanceRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='provenance'?{...p,runner:'provenance-real',executionMode:'REAL_VALIDATION',normalizer:'provenance-native/v1',policyAdapter:'provenance',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['PROVENANCE_METADATA','TRUSTED_EXECUTOR'],timeout:30000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Build Provenance's frozen Policy adapter consumes versioned
// verification facts (buildProvenanceEvidence): the runner executes
// the platform's existing DSSE/build validators over the real archived
// build attestation and reports the true exit outcome.
export function realBuildProvenanceRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='build-provenance'?{...p,runner:'build-provenance-real',executionMode:'REAL_VALIDATION',normalizer:'build-provenance-native/v1',policyAdapter:'build-provenance',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['BUILD_METADATA','TRUSTED_EXECUTOR'],timeout:30000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}

// Additive native plugin; existing managed registry remains unchanged.
// The frozen SOPS Policy adapter consumes the secrets-gate observations
// through sopsFacts/sopsDecision (infra/security/policy/sops-evidence.mjs):
// the runner supplies real controlled gate observations, never a decision.
export function realSopsRegistry(){return registry(realManagedRegistry().all().map(p=>p.pluginId==='sops'?{...p,runner:'sops-real',executionMode:'REAL_VALIDATION',normalizer:'sops-native/v1',policyAdapter:'sops',pluginVersion:'2.0.0-candidate.7',enabled:false,requiredCapabilities:['CREDENTIALS','TRUSTED_EXECUTOR'],timeout:120000,cleanupPolicy:'TERMINATE_AND_VERIFY_GROUP'}:p));}
