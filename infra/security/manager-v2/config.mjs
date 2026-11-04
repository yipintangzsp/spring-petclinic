// Candidate-only configuration. The authoritative engine owns every rule decision.
import fs from 'node:fs';
import {resolvePolicy} from '../policy/engine.mjs';
import {object,fail,freeze,digest,sha} from '../summary-v2/codec.mjs';
export const PROFILES=Object.freeze(['java-web','python-api','container-service','infra-k8s','iac']);
const levels=['low','standard','strict'];
export const identity=x=>{if(typeof x!=='string'||!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$/.test(x))fail('invalid identity');return x;};
export function keys(x,allowed){if(!object(x)||Object.keys(x).some(k=>!allowed.includes(k)))fail('unknown configuration key or invalid object');}
function plugins(x,ids){
 keys(x,ids);for(const v of Object.values(x)){keys(v,['enabled']);if(typeof v.enabled!=='boolean')fail('plugin enabled must be boolean');}
 return structuredClone(x);
}
export function configuration(input={},projectId,ids=['gitleaks','semgrep','cosign','trivy'],defaults={}){
 identity(projectId);keys(input,['security','profilePolicies','componentOverrides','projectOverrides']);
 const s=input.security===undefined?{}:input.security;keys(s,['enabled','globalMode','securityLevel','profile','policyVersion','plugins']);
 if(s.enabled!==undefined&&typeof s.enabled!=='boolean')fail('enabled must be boolean');
 if(s.globalMode!==undefined&&!['off','audit','enforce'].includes(s.globalMode)||s.securityLevel!==undefined&&!levels.includes(s.securityLevel))fail('invalid explicit mode/level');
 if(s.policyVersion!==undefined)version(s.policyVersion);
 const profile=s.profile??'java-web';if(!PROFILES.includes(profile))fail('unknown profile');
 const provenance=[{layer:'global',securityLevel:'standard',policyVersion:'baseline-v1'}];
 keys(defaults,ids);if(Object.values(defaults).some(v=>typeof v!=='boolean'))fail('registry defaults');
 let effective={enabled:true,globalMode:'audit',securityLevel:'standard',profile,policyVersion:'baseline-v1',plugins:Object.fromEntries(ids.map(id=>[id,{enabled:defaults[id]??true}]))};
 provenance.push({layer:'registryDefaults',plugins:structuredClone(effective.plugins)});
 const profilePolicies=input.profilePolicies===undefined?{}:input.profilePolicies;keys(profilePolicies,PROFILES);
 for(const p of Object.values(profilePolicies)){keys(p,['securityLevel','policyVersion','plugins','policyOverrides']);if(p.plugins!==undefined)plugins(p.plugins,ids);if(p.policyOverrides!==undefined)resolvePolicy({componentOverrides:p.policyOverrides});if(p.securityLevel!==undefined&&!levels.includes(p.securityLevel))fail('profile level');if(p.policyVersion!==undefined)version(p.policyVersion);}
 const apply=(layer,p)=>{
  for(const k of ['enabled','globalMode','securityLevel','policyVersion'])if(p[k]!==undefined)effective[k]=p[k];
  if(p.plugins!==undefined)Object.assign(effective.plugins,plugins(p.plugins,ids));
  provenance.push({layer,values:structuredClone(p)});
 };
 const pp=profilePolicies[profile]??{};apply('globalExplicit',s);
 // Profile settings outrank global explicit settings, matching documented inheritance.
 apply('profile',pp);
 const components=input.componentOverrides===undefined?{}:input.componentOverrides;keys(components,ids);
 const policies={...(pp.policyOverrides??{})};
 for(const [id,c]of Object.entries(components)){
  keys(c,['enabled','policy']);if(c.enabled!==undefined){if(typeof c.enabled!=='boolean')fail('component enabled');effective.plugins[id]={enabled:c.enabled};}
  if(c.policy!==undefined){policies[id]=c.policy;resolvePolicy({componentOverrides:{[id]:c.policy}});}
  provenance.push({layer:'component',component:id,values:structuredClone(c)});
 }
 const projects=input.projectOverrides===undefined?{}:input.projectOverrides;if(!object(projects))fail('projectOverrides must be object');
 for(const [id,p]of Object.entries(projects)){
  identity(id);keys(p,['securityLevel','policyVersion','plugins','policyOverrides']);
  if(p.plugins!==undefined)plugins(p.plugins,ids);if(p.securityLevel!==undefined&&!levels.includes(p.securityLevel))fail('project level');
  if(p.policyVersion!==undefined)version(p.policyVersion);if(p.policyOverrides!==undefined)resolvePolicy({componentOverrides:p.policyOverrides});
 }
 const project=projects[projectId]??{};apply('project',project);
 if(!['off','audit','enforce'].includes(effective.globalMode)||!levels.includes(effective.securityLevel))fail('invalid mode/securityLevel');
 const descriptor=version(effective.policyVersion);
 if(descriptor.requiredLevel){if([s,pp,project].some(p=>p.securityLevel!==undefined)&&effective.securityLevel!==descriptor.requiredLevel)fail('policy/level conflict');effective.securityLevel=descriptor.requiredLevel;}
 const policyConfig={policyVersion:descriptor.enginePolicyVersion,securityLevel:effective.securityLevel,profile,mode:'enforce',project:projectId,componentOverrides:policies};
 if(project.policyOverrides)policyConfig.projectOverride={project:projectId,components:project.policyOverrides};
 const resolved=resolvePolicy(policyConfig);
 return freeze({...effective,projectId,policySource:{...descriptor,descriptorDigest:digest(descriptor)},effectiveSecurityLevel:effective.securityLevel,effectiveProfile:profile,
  effectivePolicy:resolved.effectivePolicy,appliedOverrides:resolved.appliedOverrides,configurationOrigins:provenance,policyConfig,configDigest:digest(input),effectiveConfigDigest:digest({effective,projectId,policyConfig})});
}
export function version(id){
 if(!['baseline-v1','baseline-v2','strict-v1'].includes(id))fail('unknown policy version');
 const d=JSON.parse(fs.readFileSync(new URL('./policies/'+id+'.json',import.meta.url)));
 if(d.policyVersion!==id||d.enginePolicyVersion!=='baseline-v1'||d.candidateOnly!==true)fail('invalid policy descriptor');
 for(const [p,h]of Object.entries(d.sourceHashes))if(sha(fs.readFileSync(new URL('../../../'+p,import.meta.url)))!==h)fail('policy source changed');
 return d;
}
