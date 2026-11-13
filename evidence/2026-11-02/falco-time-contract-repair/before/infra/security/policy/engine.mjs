import {zapParent} from './zap-parent.mjs';
import {trivyParent} from './trivy-parent.mjs';
import {gitleaksParent} from './gitleaks-parent.mjs';
import {promotionEvidence} from './promotion-evidence.mjs';
import {commandParent} from './command-parent.mjs';
import {regressionEvidence} from './regression-evidence.mjs';
import {sbomParent} from './sbom-parent.mjs';
import {buildProvenanceWorkflow} from './build-provenance-workflow.mjs';
import {buildProvenanceEvidence} from './build-provenance-evidence.mjs';
import {provenanceWorkflow} from './provenance-workflow.mjs';
import {provenanceParent} from './provenance-parent.mjs';
import {cosignParent} from './cosign-parent.mjs';
import {falcoParent} from './falco-parent.mjs';
import {dojoParent} from './dojo-parent.mjs';
import {kubescapeParent} from './kubescape-parent.mjs';
import {kyvernoParent} from './kyverno-parent.mjs';
import {admissionEvidence,rbacEvidence} from './kyverno-evidence.mjs';
import {sopsFacts,sopsDecision} from './sops-evidence.mjs';
import {commandEvidence} from './command-evidence.mjs';
import {frozenContractEvidence,frozenContracts} from './frozen-contract-evidence.mjs';
import {sbomEvidence} from './sbom-evidence.mjs';
import {sonarDecision} from './sonar-evidence.mjs';
import {gitleaksEvidence} from './gitleaks-evidence.mjs';
import {classifySemgrep} from '../semgrep-policy.mjs';
import {classifyVulnerability} from '../trivy-medium-policy.mjs';
import {classifyZap} from '../zap-policy.mjs';
import fs from 'node:fs';
const error=message=>{throw Error('POLICY_ERROR: '+message);};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const severities=['Critical','High','Medium','Low','Info'];
const components=['security-approval-promotion','regression','gitleaks','semgrep','sonarqube','sbom','trivy','cosign','kubescape','zap','defectdojo','provenance','build-provenance','sops','falco-baseline','falco-final','kyverno','kyverno-admission','kyverno-rbac','falco','semgrep-command-audit',...frozenContracts];
const decisions=['PASS','WARN','FAIL'];
function patch(x){
 if(!object(x)||Object.keys(x).some(k=>!severities.includes(k))||Object.values(x).some(v=>!decisions.includes(v)))error('invalid severity override');
 return structuredClone(x);
}
export function resolvePolicy(config={}){
 if(!object(config))error('configuration must be an object');
 const version=config.policyVersion??'baseline-v1';
 if(version!=='baseline-v1')error('unknown policy version');
 let data;try{data=JSON.parse(fs.readFileSync(new URL('./versions/'+version+'.json',import.meta.url)));}catch{error('policy read failed');}
 if(data.schema!==1||data.policyVersion!==version)error('invalid policy document');
 const profile=config.profile??'java-web';
 if(!Object.hasOwn(data.profiles,profile))error('unknown profile');
 const securityLevel=config.securityLevel??'standard';
 if(!Object.hasOwn(data.levels,securityLevel))error('unknown securityLevel');
 const effectivePolicy={},appliedOverrides=[];
 const selected=patch(data.levels[securityLevel]);
 if(severities.some(k=>!Object.hasOwn(selected,k)))error('incomplete baseline');
 const profilePolicy=patch(data.profiles[profile]);
 if(Object.keys(profilePolicy).length)appliedOverrides.push({layer:'profile',profile,values:profilePolicy});
 for(const id of components)effectivePolicy[id]={...selected,...profilePolicy};
 const apply=(layer,overrides)=>{
  if(overrides===undefined)return;
  if(!object(overrides))error('invalid '+layer);
  for(const [component,values]of Object.entries(overrides)){
   if(!components.includes(component))error('unknown component');
   const p=patch(values);Object.assign(effectivePolicy[component],p);appliedOverrides.push({layer,component,values:p});
  }
 };
 apply('component',config.componentOverrides);
 if(config.projectOverride!==undefined){
  const p=config.projectOverride;
  if(!object(p)||Object.keys(p).some(k=>!['project','components'].includes(k))||typeof config.project!=='string'||p.project!==config.project)error('project override identity mismatch');
  if(!object(p.components))error('project components missing');
  apply('project',p.components);
 }
 return {policyVersion:version,securityLevel,profile,effectivePolicy,appliedOverrides};
}
// Only raw observations enter; decisions are computed here, never supplied by scanners.
export function evaluate(facts,config={}){
 const policy=resolvePolicy(config);
 if(!object(facts)||!components.includes(facts.component)||!['success','error','not_configured','disabled','skipped'].includes(facts.status))error('invalid scanner facts');
 if(config.mode!==undefined&&!['off','audit','enforce'].includes(config.mode))error('invalid mode');
 if(config.mode==='off'||['disabled','skipped','not_configured'].includes(facts.status))return {...policy,decision:null,status:config.mode==='off'?'SKIPPED':facts.status.toUpperCase(),evaluations:[]};
 if(facts.status==='error')return {...policy,status:'ERROR',decision:'FAIL',evaluations:[]};
 if(facts.component==='zap'&&facts.raw?.stage)return {...policy,...zapParent(facts.raw)};
 if(facts.component==='trivy'&&facts.raw?.stage)return {...policy,...trivyParent(facts.raw)};
 if(facts.component==='gitleaks'&&facts.raw?.stage)return {...policy,...gitleaksParent(facts.raw)};
 if(facts.component==='security-approval-promotion'){return {...policy,...promotionEvidence(facts.raw)};}
 if(facts.component==='regression'){return {...policy,...regressionEvidence(facts.raw)};}
 if(['falco-baseline','falco-final'].includes(facts.component)){
  const expected=facts.component==='falco-baseline'?'baseline':'check';if(facts.raw?.mode&&facts.raw.mode!==expected)throw Error('POLICY_ERROR: Falco stage mismatch');return {...policy,...falcoParent(facts.raw)};
 }
 if(facts.component==='build-provenance'){return {...policy,...(facts.raw?.workflow?buildProvenanceWorkflow(facts.raw):buildProvenanceEvidence(facts.raw))};}
 if(facts.component==='provenance'){return {...policy,...(facts.raw?.workflow?provenanceWorkflow(facts.raw):provenanceParent(facts.raw))};}
 if(facts.component==='cosign'){return {...policy,...cosignParent(facts.raw)};}
 if(facts.component==='kubescape'){return {...policy,...kubescapeParent(facts.raw)};}
 if(facts.component==='kyverno'){return {...policy,...kyvernoParent(facts.raw)};}
 if(['kyverno-admission','kyverno-rbac'].includes(facts.component)){
  const evidence=facts.component==='kyverno-admission'?admissionEvidence(facts.raw):rbacEvidence(facts.raw);return {...policy,...evidence};
 }
 if(facts.component==='sops'){
  const normalized=sopsFacts(facts.raw);return {...policy,...sopsDecision(normalized),sopsFacts:normalized};
 }
 if(facts.component==='semgrep-command-audit'&&facts.raw?.stage){return {...policy,...commandParent(facts.raw)};}
 if(facts.component==='semgrep-command-audit'){
  const evidence=commandEvidence(facts.raw);return {...policy,status:evidence.decision,decision:evidence.decision,evaluations:[],frozenEvidence:evidence};
 }
 if(facts.component==='sbom'&&facts.raw?.stage){return {...policy,...sbomParent(facts.raw)};}
 if(facts.component==='sbom'||frozenContracts.includes(facts.component)){
  const evidence=facts.component==='sbom'?sbomEvidence(facts.raw):frozenContractEvidence(facts.component,facts.raw);
  // Frozen proof decisions are authoritative: no severity override or audit downgrade.
  return {...policy,status:evidence.decision,decision:evidence.decision,evaluations:[],frozenEvidence:evidence};
 }
 if(facts.component==='sonarqube'){
  const {decision,evidence}=sonarDecision(facts.raw);
  // Server Quality Gate is authoritative at every level; no severity reclassification.
  return {...policy,status:decision,decision,evaluations:[],sonarEvidence:evidence};
 }
 let observations;
 if(facts.component==='gitleaks'){
  observations=gitleaksEvidence(facts.raw).observations.map(x=>({rule:x.finding.rule,severity:null,baseline:x.reviewMatched?'PASS':'FAIL',reviewAccepted:x.reviewMatched}));
 }else if(facts.component==='semgrep'){
  if(!Array.isArray(facts.raw?.findings))error('Semgrep findings missing');
  const r=classifySemgrep(facts.raw.findings);
  observations=facts.raw.findings.map(f=>({rule:f.check_id??f.rule_id,severity:['ERROR','HIGH','CRITICAL'].includes(String(f.extra?.severity??f.severity).toUpperCase())?'High':'Medium',baseline:r.blocking.includes(f)?'FAIL':'WARN'}));
 }else if(facts.component==='trivy'){
  if(!Array.isArray(facts.raw?.findings)||!object(facts.raw.review)||!Array.isArray(facts.raw.review.entries))error('Trivy raw evidence missing');
  observations=facts.raw.findings.map(f=>({rule:f.id,severity:f.severity,baseline:classifyVulnerability(f,facts.raw.review,facts.raw.image).mode}));
 }else if(facts.component==='zap'){
  let r;try{r=classifyZap(facts.raw.report,facts.raw.context,facts.raw.approved);}catch{error('invalid ZAP evidence');}
  observations=[...r.blocking.map(f=>({rule:f.pluginid,severity:'High',baseline:'FAIL'})),...r.warnings.map(f=>({rule:f.pluginid,severity:['Info','Low','Medium','High'][Number(f.riskcode)],baseline:'WARN'}))];
 }else error('frozen evidence adapter not implemented: '+facts.component);
 const evaluations=observations.map(f=>{
  if(!severities.includes(f.severity)&&!(facts.component==='gitleaks'&&f.severity===null))error('invalid finding severity');
  let decision=f.baseline;
  const explicit=policy.appliedOverrides.some(x=>(!x.component||x.component===facts.component)&&Object.hasOwn(x.values,f.severity));
  if(f.severity!==null&&!f.reviewAccepted&&(explicit||policy.securityLevel==='strict'))decision=policy.effectivePolicy[facts.component][f.severity];
  // Never weaken an established mandatory failure, even via explicit override.
  if(f.baseline==='FAIL')decision='FAIL';
  if(config.mode==='audit'&&decision==='FAIL')decision='WARN';
  return {rule:f.rule,severity:f.severity,decision};
 });
 const decision=evaluations.some(x=>x.decision==='FAIL')?'FAIL':evaluations.some(x=>x.decision==='WARN')?'WARN':'PASS';
 return {...policy,status:decision,decision,evaluations};
}

// Dojo acceptance is asynchronous; synchronous evaluate never fabricates a result.
export async function evaluateAsync(facts,config={}){
 if(facts?.component!=='defectdojo'||facts.status!=='success'||config.mode==='off')return evaluate(facts,config);
 const policy=resolvePolicy(config);
 if(config.mode!==undefined&&!['off','audit','enforce'].includes(config.mode))throw Error('POLICY_ERROR: invalid mode');
 return {...policy,...await dojoParent(facts.raw)};
}
