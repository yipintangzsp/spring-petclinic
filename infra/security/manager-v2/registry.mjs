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
  const real=realCosign||realSemgrep||p.pluginId==='gitleaks'&&p.runner==='gitleaks-real'&&p.executionMode==='REAL_VALIDATION'&&p.normalizer==='gitleaks-dir/v1'&&p.cleanupPolicy==='TERMINATE_AND_VERIFY_GROUP';
  if(typeof p.enabled!=='boolean'||!Number.isSafeInteger(p.timeout)||p.timeout<1||p.timeout>30000||!real&&(!['archive-worker','blocked'].includes(p.runner)||!['OFFLINE_REPLAY','PREFLIGHT_ONLY'].includes(p.executionMode)||p.normalizer!=='preserve-raw/v1'||p.cleanupPolicy!=='TERMINATE_AND_JOIN_WORKER'))fail('untrusted runner contract');
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
 if(['gitleaks-real','semgrep-real','cosign-real'].includes(plugin.runner)&&context.platform!=='linux')return {executionStatus:'UNSUPPORTED',reason:'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY',missing:[]};
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
