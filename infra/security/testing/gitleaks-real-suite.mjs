// Run only by the reviewed unprivileged Linux fixture controller. No production I/O.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {runCandidate} from '../manager-v2/core.mjs';import {registry,realGitleaksRegistry} from '../manager-v2/registry.mjs';import {realExecutionCounts} from '../manager-v2/gitleaks-real.mjs';import {verifyArtifact} from '../manager-v2/result.mjs';import {routeResults} from '../manager-v2/router.mjs';
const approvalFile=process.argv[2],mode=process.argv[3]??'normal',approval=JSON.parse(fs.readFileSync(approvalFile));const output=approval.outputRoot,records=[];
const caps={SOURCE_DIR:{state:'AVAILABLE'},GITLEAKS_TOOL:{state:'AVAILABLE'},TRUSTED_VALIDATION_WORKSPACE:{state:'AVAILABLE'}};
const config=(enabled=true,profile='java-web')=>({security:{profile,globalMode:'audit',plugins:Object.fromEntries(registry().ids().map(id=>[id,{enabled:id==='gitleaks'&&enabled}]))}});
async function run(name,source=approval.sources[0],overrides={}){
 const options={runId:name,projectId:source.projectId,config:config(true,source.profile),registry:realGitleaksRegistry(),context:{platform:'linux',capabilities:caps},inputs:{gitleaks:{approvalFile,sourceDir:source.sourceDir}},output:path.join(output,name),...overrides};
 const before=realExecutionCounts();const result=await runCandidate(options),r=result.gate.gitleaks;
 records.push({name,sourceRevision:source.sourceRevision,executionStatus:r.executionStatus,policyDecision:r.policyDecision,evaluationCount:r.evaluationCount,resultDigest:r.resultDigest,factDigest:r.factDigest,rawReportDigest:r.rawReportDigest,oldGateDecision:r.oldGateDecision??null,processCountsBefore:before,processCountsAfter:realExecutionCounts(),failureReason:r.failureReason,promotion:result.summary.promotion,sealDigest:result.artifact.sealDigest});
 assert.strictEqual(r,result.summary.pluginResults.find(x=>x.pluginId==='gitleaks'));assert.equal(result.summary.promotion.status,'BLOCKED');assert.equal(verifyArtifact(options.output,result.artifact.sealDigest),true);assert.equal(verifyArtifact(options.output,result.artifact.sealDigest),true);
 return {result,r,options};
}
if(mode==='tool-error'){
 const {r}=await run('tool-error');assert.equal(r.executionStatus,'ERROR');assert.equal(r.policyDecision,null);assert.equal(realExecutionCounts().scans,0);assert.equal(r.evaluationCount,0);
}else{
 let writable=false;try{fs.accessSync(approvalFile,fs.constants.W_OK);writable=true;}catch{}assert.equal(writable,false);
 const a=await run('java-real-secret');assert.equal(a.r.executionStatus,'COMPLETED');assert.equal(a.r.policyDecision,'FAIL');assert.equal(a.r.oldGateDecision,'FAIL');assert.equal(a.r.evaluationCount,1);assert.equal(a.r.runtimeFacts.classification,'REAL_CONTROLLED_EXECUTION');
 const b=await run('python-real-clean',approval.sources[1]);assert.equal(b.r.executionStatus,'COMPLETED');assert.equal(b.r.policyDecision,'PASS');assert.equal(b.r.oldGateDecision,'PASS');assert.equal(b.r.evaluationCount,1);assert.equal(b.result.summary.profile,'python-api');assert.notEqual(a.r.runtimeFacts.sourceDir.path,b.r.runtimeFacts.sourceDir.path);
 const routerOut=path.join(output,'router');fs.mkdirSync(routerOut,{mode:0o700});const counts=realExecutionCounts(),args={run:a.result,artifactDirectory:a.options.output,expectedSealDigest:a.result.artifact.sealDigest,output:routerOut};
 const delivery=routeResults(args),failedDelivery=routeResults(args);assert.equal(delivery.receipts[1].deliveryDecision,'DELIVERED_LOCAL_ONLY');assert.equal(failedDelivery.receipts[1].deliveryDecision,'ERROR');assert.equal(failedDelivery.candidateDeliveryAllowed,false);assert.equal(delivery.receipts[1].resultDigests.gitleaks,a.r.resultDigest);assert.deepEqual(realExecutionCounts(),counts);assert.equal(a.result.policyEvaluationCounts.gitleaks,1);
 fs.writeFileSync(path.join(output,'router-receipts.json'),JSON.stringify({delivery,failedDelivery,executionCountsUnchanged:true,policyCounts:a.result.policyEvaluationCounts},null,2),{flag:'wx',mode:0o400});
 const master=config();master.security.enabled=false;const off=await run('master-disabled',undefined,{config:master});assert.equal(off.r.executionStatus,'DISABLED');assert.equal(off.result.summary.candidateBuildAllowed,true);assert.deepEqual(realExecutionCounts(),counts);
 const disabled=await run('plugin-disabled',undefined,{config:config(false)});assert.equal(disabled.r.executionStatus,'DISABLED');assert.deepEqual(realExecutionCounts(),counts);
 const absent=await run('source-missing',undefined,{context:{platform:'linux',capabilities:{GITLEAKS_TOOL:{state:'AVAILABLE'},TRUSTED_VALIDATION_WORKSPACE:{state:'AVAILABLE'}}}});assert.equal(absent.r.executionStatus,'NOT_CONFIGURED');assert.deepEqual(realExecutionCounts(),counts);
 const unsupported=await run('unsupported-platform',undefined,{context:{platform:'darwin',capabilities:caps}});assert.equal(unsupported.r.executionStatus,'UNSUPPORTED');assert.deepEqual(realExecutionCounts(),counts);
 const foreign=await run('foreign-source',undefined,{inputs:{gitleaks:{approvalFile,sourceDir:'/etc'}}});assert.equal(foreign.r.executionStatus,'POLICY_ERROR');assert.deepEqual(realExecutionCounts(),counts);
 const invalid=config();invalid.security.policyVersion='unknown';await assert.rejects(run('invalid-policy',undefined,{config:invalid}),/POLICY_ERROR/);assert.equal(fs.existsSync(path.join(output,'invalid-policy')),false);assert.deepEqual(realExecutionCounts(),counts);
 assert.equal(fs.readdirSync(output).some(f=>f.startsWith('scan-')),false);
}
const evidence={scope:'REAL_CONTROLLED_NON_RELEASE_FIXTURE_NOT_PRODUCTION_RUNTIME',mode,records,executionCounts:realExecutionCounts(),identity:{uid:process.getuid(),gid:process.getgid(),groups:process.getgroups()},release:0,rollout:0,canonicalRuntimeCount:'14/16'};
fs.writeFileSync(path.join(output,mode+'-suite.json'),JSON.stringify(evidence,null,2),{flag:'wx',mode:0o400});console.log(JSON.stringify({mode,status:'PASS',records:records.length,executionCounts:evidence.executionCounts}));
