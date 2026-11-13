// Dedicated Jenkins non-release entry point. Never imported by active V1.
// Runs genuine bounded Node Regression and read-only Falco Gates to validate
// collection/owner insertion; cannot certify the still-unimplemented sources.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {captureStage} from './execute.mjs';
import {createRuntimeOwner} from './owner.mjs';
import {contractFor} from './projection.mjs';
import {EXPECTED_SOURCES} from '../summary-v2/inventory.mjs';
import {writeRuntimeArtifactCandidate} from './artifact-candidate.mjs';
import {collectHelperReturn} from './helper-return.mjs';
import {prepareSbomBuildRoot} from './sbom-build-root.mjs';
import {captureNewSonar} from './sonar-execute.mjs';
import {receiveIsolatedSops} from './isolated-channel.mjs';

const output='.devsecops/runtime-facts/build-'+String(process.env.BUILD_NUMBER);fs.mkdirSync(output,{recursive:true,mode:0o700});
const k=spawnSync('kubectl',['--request-timeout=15s','-n','petclinic','get','deployment','petclinic','-o','json'],{encoding:'utf8',timeout:20000});
if(k.status!==0)throw Error('Cannot establish actual target binding');
const candidate=JSON.parse(k.stdout).spec.template.spec.containers.find(c=>c.name==='petclinic').image;
const binding={job:process.env.JOB_NAME,build:Number(process.env.BUILD_NUMBER),project:'petclinic',source:fs.readFileSync('.git-sha','utf8').trim(),candidate,targetScope:'runtime',runId:process.env.JOB_NAME+'#'+process.env.BUILD_NUMBER};
const owner=createRuntimeOwner({binding,directory:path.join(output,'results')});
const plan=JSON.parse(fs.readFileSync('resources/security-manager/petclinic-adapter.json'));
const regression=plan.find(p=>p.id==='regression');
let lease=false,buildRoot,sonarRoot;const failures=[];
async function stage(id,command){
  const log=fs.openSync(path.join(output,id+'.log'),'wx',0o600);
  let clean;
  try{
    if(id==='sbom')clean=buildRoot=prepareSbomBuildRoot();
    const run=await captureStage({sourceId:id,command,binding,cwd:clean?.directory??process.cwd(),buildInput:clean?.identity,onOutput:(_kind,b)=>fs.writeSync(log,b)});
    const result=await owner.accept(run.envelope);
    const gate=owner.reuseForGate(id,run.exitStatus===0?'success':'failed');
    console.log(JSON.stringify({sourceId:id,evaluationCount:owner.snapshot().evaluationCounts[id],resultDigest:result.resultDigest,gateResultDigest:gate.resultDigest,observedExit:run.exitStatus,policyDecision:result.result?.decision}));
  }finally{
    if(clean)fs.writeFileSync(path.join(output,'sbom-build-input.json'),JSON.stringify({...clean.identity,cleanup:'AFTER_CURRENT_SOURCE_SONAR_TRANSACTION'}));
    fs.closeSync(log);
  }
}
try{
  await stage('sbom',plan.find(p=>p.id==='sbom').command);
  await stage('regression',regression.command);
  const acquired=spawnSync(process.execPath,['infra/observability/heavy-lease.mjs','acquire'],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
  if(acquired.status!==0)throw Error('Existing heavy Lease acquisition failed; no Falco run');lease=true;
  // Relative ordering matches the unchanged production plan. Kyverno uses only
  // its original read and server dry-run calls; no workload is created.
  for(const id of ['falco-baseline','kyverno','kubescape','falco-final'])await stage(id,plan.find(p=>p.id===id).command);
  {
    const log=fs.openSync(path.join(output,'sonarqube.log'),'wx',0o600);
    try{
      sonarRoot=prepareSbomBuildRoot();
      const run=await captureNewSonar({binding,cwd:sonarRoot.directory,env:process.env,productionCommand:plan.find(p=>p.id==='sonarqube').command,onOutput:(_kind,b)=>fs.writeSync(log,b)});
      const r=await owner.accept(run.envelope),g=owner.reuseForGate('sonarqube',run.exitStatus===0?'success':'failed');
      fs.writeFileSync(path.join(output,'sonar-current-lineage.json'),JSON.stringify({executionScope:'REAL_DEDICATED_NONRELEASE_NEW_ANALYSIS',binding,raw:run.envelope.facts.raw,rawFactDigest:r.rawFactDigest,resultDigest:r.resultDigest,gateResultDigest:g.resultDigest,negativeCompatibility:'DEFERRED_REAL_NEGATIVE_EVIDENCE'},null,2));
    }catch(e){failures.push({sourceId:'sonarqube',code:'SONAR_RUNTIME_LINEAGE_BLOCKED',message:e.message});}finally{fs.closeSync(log);if(sonarRoot){sonarRoot.cleanup();fs.writeFileSync(path.join(output,'sonar-build-input.json'),JSON.stringify({...sonarRoot.identity,cleanupComplete:!fs.existsSync(sonarRoot.directory)}));}}
  }
  {
    try{
      const run=await receiveIsolatedSops({binding,output});
      const r=await owner.accept(run.envelope),g=owner.reuseForGate('sops',run.oldExit===0?'success':'failed');
      fs.writeFileSync(path.join(output,'sops-runtime-receipt.json'),JSON.stringify({executionScope:'CONTROLLED_ISOLATED_RUNTIME',binding,guard:run.guard,oldExit:run.oldExit,policyDecision:r.result?.decision,rawFactDigest:r.rawFactDigest,resultDigest:r.resultDigest,gateResultDigest:g.resultDigest,productionSecretAccess:0,productionAgeKeyAccess:0}));
    }catch(e){failures.push({sourceId:'sops',code:'ISOLATED_SOPS_RUNTIME_BLOCKED',message:e.message});}
  }
  // These facts are real original CPS returns captured by the dedicated job,
  // not guessed from missing reports or selected by new plugin switches.
  for(const id of ['provenance','build-provenance']){
    const e=collectHelperReturn({sourceId:id,binding,path:path.join(output,'helper-returns',id+'.json')});
    const r=await owner.accept(e),g=owner.reuseForGate(id,e.facts.raw.observedReturn.status);
    console.log(JSON.stringify({sourceId:id,evaluationCount:owner.snapshot().evaluationCounts[id],resultDigest:r.resultDigest,gateResultDigest:g.resultDigest,originalReturn:e.facts.raw.observedReturn.status,policyStatus:r.result?.status}));
  }
}catch(e){failures.push({code:'RUNTIME_CAPTURE_OR_OWNER_ERROR',message:e.message});}
finally{
  if(buildRoot){buildRoot.cleanup();fs.writeFileSync(path.join(output,'sbom-build-input.json'),JSON.stringify({...buildRoot.identity,cleanupComplete:!fs.existsSync(buildRoot.directory)}));}
  if(lease){const r=spawnSync(process.execPath,['infra/observability/heavy-lease.mjs','release'],{encoding:'utf8'});if(r.status!==0)failures.push({code:'LEASE_RELEASE_FAILED'});}
}
const snapshot=owner.snapshot();
const coverage={classification:'REAL_DEDICATED_NONRELEASE_JENKINS_EXECUTION',binding,sources:EXPECTED_SOURCES.map(id=>({sourceId:id,
  evaluationCount:snapshot.evaluationCounts[id]??null,resultDigest:snapshot.sources.find(r=>r.sourceId===id)?.resultDigest??null,
  state:snapshot.sources.some(r=>r.sourceId===id)?'CAPTURED': 'NOT_OBSERVED',contract:contractFor(id)})),missing:snapshot.missing,
  gate:snapshot.gate,failures,complete:snapshot.complete,artifactGenerated:false,summaryActivated:false,promotion:0,release:0,rollout:0};
// Completeness rejection is exercised in the actual path, not silently filled.
try{
  writeRuntimeArtifactCandidate({snapshot});
  throw Error('Unexpected complete artifact without all real sources');
}catch(e){coverage.artifactRejection=e.message;}
fs.writeFileSync(path.join(output,'coverage.json'),JSON.stringify(coverage,null,2));
console.log(JSON.stringify({captured:snapshot.sources.length,expected:EXPECTED_SOURCES.length,missing:snapshot.missing,artifact:'INCOMPLETE',release:0,rollout:0}));
process.exitCode=3; // Real partial proof is never a green full-integration result.
