import {digest,fail,freeze} from '../../summary-v2/codec.mjs';
import {registry} from '../registry.mjs';

export const JOB='security-manager-v2-gitleaks-validation';
export const AGENT='gitleaks-validation-restricted';
export const RELEASE='/opt/security-manager-v2-validation/releases/gitleaks-ci-v1';
export const MANAGER_COMMIT='2ca60f7';
export const PROJECTS=freeze({'java-fixture':'java-web','python-fixture':'python-api'});
export const CASES=freeze({
 'master-off':{status:'DISABLED',decision:null,scans:0,evaluations:0},
 'plugin-off':{status:'DISABLED',decision:null,scans:0,evaluations:0},
 clean:{status:'COMPLETED',decision:'PASS',scans:1,evaluations:1},
 secret:{status:'COMPLETED',decision:'FAIL',scans:1,evaluations:1},
 'missing-capability':{status:'NOT_CONFIGURED',decision:null,scans:0,evaluations:0},
 'runner-error':{status:'ERROR',decision:null,scans:0,evaluations:0},
 'policy-error':{status:'POLICY_ERROR',decision:null,scans:0,evaluations:0}
});
const names=['SECURITY_ENABLED','GLOBAL_MODE','SECURITY_LEVEL','PROFILE','POLICY_VERSION','GITLEAKS_ENABLED','VALIDATION_PROJECT','VALIDATION_RUN_ID','VALIDATION_CASE'];
const flag=(x,name)=>{if(typeof x!=='boolean')fail(name+' must be a boolean');return x;};
export function resolveCI(parameters,ci){
 if(!parameters||typeof parameters!=='object'||Array.isArray(parameters)||Object.keys(parameters).some(k=>!names.includes(k)))fail('CI parameter allowlist');
 if(ci?.job!==JOB||!Number.isSafeInteger(ci.build)||ci.build<1||ci.build>999999999||ci.node!==AGENT)fail('CI identity not approved');
 const p={SECURITY_ENABLED:true,GLOBAL_MODE:'audit',SECURITY_LEVEL:'standard',PROFILE:'java-web',POLICY_VERSION:'baseline-v1',GITLEAKS_ENABLED:true,VALIDATION_PROJECT:'java-fixture',VALIDATION_RUN_ID:'',VALIDATION_CASE:'clean',...parameters};
 flag(p.SECURITY_ENABLED,'SECURITY_ENABLED');flag(p.GITLEAKS_ENABLED,'GITLEAKS_ENABLED');
 if(p.GLOBAL_MODE!=='audit'||p.SECURITY_LEVEL!=='standard'||p.POLICY_VERSION!=='baseline-v1')fail('CI validation policy is fixed; no fallback');
 if(!Object.hasOwn(PROJECTS,p.VALIDATION_PROJECT)||PROJECTS[p.VALIDATION_PROJECT]!==p.PROFILE||!Object.hasOwn(CASES,p.VALIDATION_CASE))fail('CI project/profile/case allowlist');
 const id='ci-'+ci.build+'-'+digest({job:ci.job,build:ci.build,project:p.VALIDATION_PROJECT,case:p.VALIDATION_CASE}).slice(0,8);
 if(p.VALIDATION_RUN_ID!==''&&p.VALIDATION_RUN_ID!==id)fail('CI run id must equal bound identity');
 if(p.VALIDATION_CASE==='master-off')p.SECURITY_ENABLED=false;
 if(p.VALIDATION_CASE==='plugin-off')p.GITLEAKS_ENABLED=false;
 let expected=CASES[p.VALIDATION_CASE];
 if(!p.SECURITY_ENABLED||!p.GITLEAKS_ENABLED)expected=CASES['plugin-off'];
 const config={security:{enabled:p.SECURITY_ENABLED,globalMode:'audit',securityLevel:'standard',profile:p.PROFILE,policyVersion:'baseline-v1',plugins:Object.fromEntries(registry().ids().map(plugin=>[plugin,{enabled:plugin==='gitleaks'&&p.GITLEAKS_ENABLED}]))}};
 if(p.VALIDATION_CASE==='policy-error'){
  if(!p.SECURITY_ENABLED||!p.GITLEAKS_ENABLED)fail('policy-error requires enabled switches');
  config.security.policyVersion='controlled-invalid-ci-policy';
 }
 return freeze({parameters:{...p,VALIDATION_RUN_ID:id},runId:id,projectId:p.VALIDATION_PROJECT,config,expected,ci:{job:ci.job,build:ci.build,node:ci.node},promotion:'BLOCKED',release:0,rollout:0});
}
export function assertIdentity(x){
 if(x.platform!=='linux'||x.node!==AGENT||!Number.isSafeInteger(x.uid)||x.uid<10000||x.uid===65534||x.approvedExecutionUid!==x.uid||x.gid!==x.uid||!Array.isArray(x.groups)||x.groups.some(g=>g!==x.uid)||x.exclusiveUidDomain!==true||x.noNewPrivs!==true||x.capEff!=='0'||x.dockerReadable!==false||x.kubeconfigReadable!==false||x.serviceAccountTokenReadable!==false||x.releaseCredentialsPresent!==false)fail('CI_EXECUTION_NOT_READY: restricted Agent identity not proven');
 return true;
}
export function evaluationIdentity(resolved,factDigest){
 return digest({kind:'CandidateCIEvaluationIdentity',ci:resolved.ci,runId:resolved.runId,plugin:'gitleaks',factDigest});
}
export function verifyExpected(resolved,result,counts){
 const e=resolved.expected;
 if(result.executionStatus!==e.status||result.policyDecision!==e.decision||result.evaluationCount!==e.evaluations||counts.scans!==e.scans)fail('CI expected-result mismatch');
 return {ciExecutionResult:e.decision==='FAIL'?'EXPECTED_POLICY_FAIL':e.status==='COMPLETED'?'EXPECTED_POLICY_PASS':'EXPECTED_'+e.status,securityPolicyDecision:result.policyDecision,promotion:'BLOCKED',expectedCase:resolved.parameters.VALIDATION_CASE};
}
