// Future restricted Agent entry; never executed on the current built-in controller.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
import {JOB,AGENT,RELEASE,MANAGER_COMMIT,resolveCI,assertIdentity,evaluationIdentity,verifyExpected} from './contract.mjs';
import {runCandidate} from '../core.mjs';import {realGitleaksRegistry} from '../registry.mjs';
import {realExecutionCounts} from '../gitleaks-real.mjs';import {routeResults} from '../router.mjs';
import {artifactStore,verifyArtifact} from '../result.mjs';import {digest,sha,fail} from '../../summary-v2/codec.mjs';

function rootFile(name){const s=fs.lstatSync(name);if(fs.realpathSync(name)!==name||!s.isFile()||s.uid!==0||(s.mode&0o022))fail('untrusted CI release file');return fs.readFileSync(name);}
export function inspectIdentity(){
 const readable=p=>{try{fs.accessSync(p,fs.constants.R_OK);return true;}catch{return false;}};
 const status=process.platform==='linux'?fs.readFileSync('/proc/self/status','utf8'):'';
 let approvedExecutionUid=null,exclusiveUidDomain=false;
 try{
  approvedExecutionUid=JSON.parse(rootFile(RELEASE+'/fixture-bindings.json')).executionUid;
  const own=fs.readFileSync('/proc/self/cgroup','utf8');
  exclusiveUidDomain=/^0::\/system\.slice\/security-manager-v2-validation-[a-f0-9]+\.service\n?$/.test(own);
  for(const p of fs.readdirSync('/proc').filter(x=>/^\d+$/.test(x))){
   try{const s=fs.readFileSync('/proc/'+p+'/status','utf8');if(Number(s.match(/^Uid:\s+(\d+)/m)?.[1])===process.getuid()&&fs.readFileSync('/proc/'+p+'/cgroup','utf8')!==own)exclusiveUidDomain=false;}
   catch(e){if(e.code!=='ENOENT'&&e.code!=='ESRCH')exclusiveUidDomain=false;}
  }
 }catch{exclusiveUidDomain=false;}
 return {platform:process.platform,node:process.env.NODE_NAME,uid:process.getuid?.(),gid:process.getgid?.(),groups:process.getgroups?.(),approvedExecutionUid,exclusiveUidDomain,noNewPrivs:/^NoNewPrivs:\s+1$/m.test(status),capEff:/^CapEff:\s+0+$/m.test(status)?'0':'UNKNOWN',dockerReadable:readable('/run/docker.sock'),kubeconfigReadable:readable('/etc/rancher/k3s/k3s.yaml'),serviceAccountTokenReadable:readable('/var/run/secrets/kubernetes.io/serviceaccount/token'),releaseCredentialsPresent:['HARBOR_PASS','HARBOR_PASSWORD','KUBECONFIG','GIT_ASKPASS','SSH_AUTH_SOCK','SIGNING_AGE_FILE','JENKINS_PASS'].some(k=>process.env[k]!==undefined)};
}
export function verifyRelease(){
 const bytes=rootFile(RELEASE+'/manifest.json');const m=JSON.parse(bytes);
 if(m.managerCommit!==MANAGER_COMMIT||m.scope!=='GITLEAKS_VALIDATION_ONLY')fail('CI release identity');
 for(const [name,h] of Object.entries(m.files)){
  if(path.isAbsolute(name)||name.split('/').some(x=>['..','.',''].includes(x))||sha(rootFile(RELEASE+'/'+name))!==h)fail('CI release source changed');
 }
 if(!m.files['infra/security/manager-v2/ci/entry.mjs']||!m.files['infra/security/manager-v2/ci/contract.mjs'])fail('CI release incomplete');
 return sha(bytes);
}
async function main(){
 assertIdentity(inspectIdentity());const releaseDigest=verifyRelease();
 if(process.argv.length!==2)fail('CI arguments prohibited');
 const request=fs.readFileSync('ci-request.json');if(request.length>16384)fail('CI request budget');
 const ci={job:process.env.JOB_NAME,build:Number(process.env.BUILD_NUMBER),node:process.env.NODE_NAME};
 const resolved=resolveCI(JSON.parse(request),ci);
 // Only the operator-owned binding can supply fixture paths. No parameter paths.
 const bindings=JSON.parse(rootFile(RELEASE+'/fixture-bindings.json'));
 if(bindings.schemaVersion!==1||bindings.agent!==AGENT||bindings.job!==JOB||bindings.executionUid!==process.getuid())fail('CI fixture binding');
 const fixture=bindings.fixtures[resolved.projectId]?.[resolved.parameters.VALIDATION_CASE];
 if(!fixture||typeof fixture.approvalFile!=='string'||typeof fixture.sourceDir!=='string')fail('CI_EXECUTION_NOT_READY: operator fixture not provisioned');
 const out=path.join(fs.realpathSync(process.cwd()),'ci-evidence');
 fs.mkdirSync(out,{mode:0o700});
 const caps={SOURCE_DIR:{state:resolved.parameters.VALIDATION_CASE==='missing-capability'?'NOT_CONFIGURED':'AVAILABLE'},GITLEAKS_TOOL:{state:'AVAILABLE'},TRUSTED_VALIDATION_WORKSPACE:{state:'AVAILABLE'}};
 const before=realExecutionCounts();let run,result,router=null,evaluationId=null,policyError=null;
 try{
  run=await runCandidate({config:resolved.config,projectId:resolved.projectId,runId:resolved.runId,registry:realGitleaksRegistry(),context:{platform:process.platform,capabilities:caps},inputs:resolved.parameters.VALIDATION_CASE==='missing-capability'?{}:{gitleaks:{approvalFile:fixture.approvalFile,sourceDir:fixture.sourceDir}},output:path.join(out,'manager')});
  result=run.gate.gitleaks;
  if(run.summary.promotion.status!=='BLOCKED'||run.summary.productionEvidence!==false)fail('CI production promotion prohibited');
  if(result.evaluationCount===1)evaluationId=evaluationIdentity(resolved,result.factDigest);
  const rdir=path.join(out,'router');fs.mkdirSync(rdir,{mode:0o700});const counts=realExecutionCounts();
  const args={run,artifactDirectory:path.join(out,'manager'),expectedSealDigest:run.artifact.sealDigest,output:rdir};
  router={success:routeResults(args),controlledFailure:routeResults(args)};
  if(router.success.receipts[1].deliveryDecision!=='DELIVERED_LOCAL_ONLY'||router.controlledFailure.receipts[1].deliveryDecision!=='ERROR'||digest(counts)!==digest(realExecutionCounts()))fail('CI Router verification');
  const summaryResult=run.summary.pluginResults.find(p=>p.pluginId==='gitleaks');
  if(summaryResult!==result||router.success.receipts[1].resultDigests.gitleaks!==result.resultDigest)fail('CI digest not reused');
  if(result.executionStatus==='COMPLETED'&&(result.oldGateDecision!==result.policyDecision||run.policyEvaluationCounts.gitleaks!==1))fail('CI old Gate/Policy mismatch');
 }catch(e){
  if(resolved.parameters.VALIDATION_CASE!=='policy-error'||!e.message.startsWith('POLICY_ERROR: unknown policy'))throw e;
  policyError=e.message;result={executionStatus:'POLICY_ERROR',policyDecision:null,evaluationCount:0};
 }
 const after=realExecutionCounts(),counts={scans:after.scans-before.scans,commands:after.commands-before.commands};
 const expected=verifyExpected(resolved,result,counts),store=artifactStore(path.join(out,'ci-receipt'));
 store.put('ci-execution.json',{schemaVersion:1,kind:'CandidateCIValidationReceipt',ci:resolved.ci,validationRunId:resolved.runId,managerCommit:MANAGER_COMMIT,managerVersion:run?.summary.managerVersion??null,releaseDigest,parameters:resolved.parameters,expected,evaluationId,evaluationCount:result.evaluationCount,factDigest:result.factDigest??null,resultDigest:result.resultDigest??null,rawReportDigest:result.rawReportDigest??null,policyError,managerArtifactSeal:run?.artifact.sealDigest??null,counts,router,identity:inspectIdentity(),canonicalRuntime:'14/16',productionEvidence:false,cleanup:{privateScannerDirectory:result.cleanup??'NOT_STARTED',operatorSourceCleanup:'PENDING_OPERATOR_PROOF'},release:0,rollout:0});
 const seal=store.finish();verifyArtifact(store.directory,seal.sealDigest);
 fs.writeFileSync(path.join(out,'ci-seal.json'),JSON.stringify(seal)+'\n',{flag:'wx',mode:0o400});
 console.log(JSON.stringify({ciExecutionResult:expected.ciExecutionResult,securityPolicyDecision:result.policyDecision,seal:seal.sealDigest,evaluationId,promotion:'BLOCKED',canonicalRuntime:'14/16',release:0,rollout:0}));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{await main();}catch(e){console.error(JSON.stringify({status:'CI_EXECUTION_NOT_READY_OR_FAILED',error:e.message.startsWith('POLICY_ERROR:')?e.message:'CI_ENTRY_REJECTED',productionPromotion:'BLOCKED'}));process.exitCode=2;}}
