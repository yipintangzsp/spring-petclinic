import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';import {BUILTINS,registry} from '../../../infra/security/manager-v2/registry.mjs';
import {digest} from '../../../infra/security/summary-v2/codec.mjs';
const reg=registry(BUILTINS.filter(p=>p.pluginId==='sbom')),tmp=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'sbom-switch-'))),rows=[];
try{
 for(const [name,enabled,mode,pluginEnabled]of [['global-off',false,'audit',true],['plugin-off',true,'audit',false],['mode-off',true,'off',true],['no-runner',true,'audit',true]]){
  // Input digest projection is part of Core; the provided input has no reader/executable or generation action.
  const config={security:{enabled,globalMode:mode,profile:'java-web',plugins:{sbom:{enabled:pluginEnabled}}}};
  const r=await runCandidate({config,runId:'sbom-switch-'+name,projectId:'portable-example',registry:reg,context:{platform:'darwin',capabilities:{SBOM_FILE:{state:'AVAILABLE'}}},inputs:{sbom:{kind:'NO_EXECUTABLE_INPUT'}},output:path.join(tmp,name)});
  const p=r.gate.sbom;assert.equal(p.evaluationCount,0);assert.equal(p.policyDecision,null);assert.equal(p.rawReportDigest,null);
  assert.equal(p.executionStatus,name==='no-runner'?'NOT_CONFIGURED':'DISABLED');
  rows.push({name,executionStatus:p.executionStatus,policyEvaluations:p.evaluationCount,rawReportProduced:false,externalOperations:0});
 }
 const x=JSON.parse(fs.readFileSync('evidence/2026-11-06/sbom-digest-link/inspection.json'));
 const candidate=x.candidate,sbom=x.sbom;
 assert.equal(sbom.actualSha256,sbom.summary.body.sha256);assert.equal(candidate.jarSha256,candidate.contextJar.sha256);
 assert.equal(candidate.provenanceContainsSbomReference,false);assert.equal(x.possibleBindingDocuments.find(d=>d.path==='.devsecops/candidate-sbom.json').candidateBuild,null);
 // No candidate SBOM verifier exists; digest-negative runtime validation is NOT_TESTED.
 const result={at:new Date().toISOString(),digestMismatchTest:'NOT_TESTED_NO_BINDING_VERIFIER',registryPlugin:{pluginId:reg.get('sbom').pluginId,runner:reg.get('sbom').runner,executionMode:reg.get('sbom').executionMode},checks:rows,sourceHashChecks:'MATCHED',SBOM_SWITCH_BEHAVIOR:'VERIFIED_EXISTING_CORE_ONLY',SBOM_PLUGIN_INTEGRATION:'INCOMPLETE',reason:'SBOM live runner and web toggle not wired; no new verifier or generator added'};
 fs.writeFileSync('evidence/2026-11-06/sbom-digest-link/checks.json',JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));
}finally{fs.rmSync(tmp,{recursive:true});}
