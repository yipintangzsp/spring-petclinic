// All three native tools execute in this same non-production Manager process.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {runCandidate} from '../manager-v2/core.mjs';import {registry,realThreePluginsRegistry} from '../manager-v2/registry.mjs';
import {realExecutionCounts} from '../manager-v2/gitleaks-real.mjs';import {semgrepExecutionCounts} from '../manager-v2/semgrep-real.mjs';import {cosignExecutionCounts} from '../manager-v2/cosign-real.mjs';
import {verifyArtifact} from '../manager-v2/result.mjs';import {routeResults} from '../manager-v2/router.mjs';import {digest,sha} from '../summary-v2/codec.mjs';
const root=process.argv[2],prefix=process.argv[3]??'',a=JSON.parse(fs.readFileSync(root+'/cosign-approval.json')),s=JSON.parse(fs.readFileSync(root+'/semgrep-approval.json')),sources=Object.fromEntries(s.sources.map(s=>[s.case,s])),out=a.outputRoot,records=[];
assert.match(prefix,/^(?:attempt[1-9][0-9]*-)?$/);
const ids=['gitleaks','semgrep','cosign'],allCaps=Object.fromEntries([...new Set(realThreePluginsRegistry().all().filter(p=>ids.includes(p.pluginId)).flatMap(p=>p.requiredCapabilities))].map(k=>[k,{state:'AVAILABLE'}]));
const counts=()=>({gitleaks:realExecutionCounts(),semgrep:semgrepExecutionCounts(),cosign:cosignExecutionCounts()});
async function run(name,{enabled=ids,master=true,mode='audit',project='java-fixture',profile='java-web',source='clean',gsource=source,ssource=source,object='valid',expected={gitleaks:'PASS',semgrep:'PASS',cosign:'PASS'},status={},cosignTimeout=null,caps=allCaps,cosignOverride=null}={}){
 name=prefix+name;const before=counts(),c={security:{enabled:master,globalMode:mode,securityLevel:'standard',policyVersion:'baseline-v1',profile,plugins:Object.fromEntries(registry().ids().map(id=>[id,{enabled:enabled.includes(id)}]))}};
 const definitions=cosignTimeout?registry(realThreePluginsRegistry().all().map(p=>p.pluginId==='cosign'?{...p,timeout:cosignTimeout}:p)):realThreePluginsRegistry();
 const dir=path.join(out,name),options={config:c,registry:definitions,runId:name,projectId:project,context:{platform:'linux',capabilities:caps},inputs:{gitleaks:{approvalFile:root+'/approval.json',sourceDir:sources[gsource].sourceDir},semgrep:{approvalFile:root+'/semgrep-approval.json',sourceDir:sources[ssource].sourceDir},cosign:{approvalFile:root+'/cosign-approval.json',objectId:cosignOverride??project+'-'+object}},output:dir};
 const r=await runCandidate(options),after=counts();
 const target={};for(const id of ids){const p=r.gate[id],st=!master||mode==='off'||!enabled.includes(id)?'DISABLED':status[id]??'COMPLETED',decision=st==='COMPLETED'?expected[id]:null;assert.equal(p.executionStatus,st,name+' '+id+' '+JSON.stringify(p.failureReason));assert.equal(p.policyDecision,decision,name+' '+id);assert.equal(p.evaluationCount,st==='COMPLETED'?1:0);assert.strictEqual(p,r.summary.pluginResults.find(x=>x.pluginId===id));
  if(st==='COMPLETED'){
   assert.equal(p.oldGateDecision,decision);assert.equal(r.policyEvaluationCounts[id],1);const raw=fs.readFileSync(path.join(dir,id+'.raw.json'),'utf8'),facts=JSON.parse(fs.readFileSync(path.join(dir,id+'.facts.json')));assert.equal(sha(raw),p.rawReportDigest);assert.equal(digest(facts),p.factDigest);assert.equal(p.policy.factDigest,p.factDigest);assert.equal(p.runtimeFacts.classification,'REAL_CONTROLLED_EXECUTION');
   if(id==='cosign'){const original=JSON.parse(raw);assert.deepEqual(facts.raw,original);assert.equal(original.trust.authorizedProject,project);assert.equal(original.trust.scope,'CONTROLLED_TEST_ONLY_NOT_PRODUCTION');assert.equal(original.command.exitStatus===0,decision==='PASS');}
  }
  target[id]={executionStatus:p.executionStatus,policyDecision:p.policyDecision,oldGateDecision:p.oldGateDecision??null,evaluationCount:p.evaluationCount,rawReportDigest:p.rawReportDigest,factDigest:p.factDigest,resultDigest:p.resultDigest,failureReason:p.failureReason};
 }
 for(const id of ids){const key=id==='cosign'?'verifications':'scans',want=target[id].executionStatus==='COMPLETED'?1:0;assert.equal(after[id][key]-before[id][key],want,name+' actual native '+id);if(target[id].executionStatus==='DISABLED')assert.deepEqual(after[id],before[id]);}
 assert.equal(verifyArtifact(dir,r.artifact.sealDigest),true);assert.equal(r.summary.promotion.status,'BLOCKED');assert.equal(r.summary.productionEvidence,false);assert.equal(r.summary.validationRunId,name);assert.equal(r.summary.overallDecision,r.summary.overallStatus);
 if(ids.every(id=>target[id].executionStatus==='DISABLED')){assert.equal(r.summary.overallStatus,'DISABLED');assert.equal(r.summary.candidateBuildAllowed,true);}
 if(ids.some(id=>target[id].executionStatus==='ERROR')){assert.equal(r.summary.overallStatus,'ERROR');assert.equal(r.summary.candidateBuildAllowed,false);}
 if(ids.some(id=>target[id].policyDecision==='FAIL'))assert.equal(r.summary.overallStatus,'FAIL');
 records.push({name,classification:'REAL_CONTROLLED_SAME_MANAGER_THREE_NATIVE_PLUGINS',projectId:project,profile,enabled,master,globalMode:mode,plugins:target,countsBefore:before,countsAfter:after,policyCounts:r.policyEvaluationCounts,overallStatus:r.summary.overallStatus,promotion:r.summary.promotion,artifactSeal:r.artifact.sealDigest});
 console.log(JSON.stringify({name,status:'PASS',plugins:target,countsBefore:before,countsAfter:after}));return {r,dir};
}
// Keys were generated and removed by the trusted preparation controller before
// this process. No production keys/registry/signing capability is injected.
assert.equal(fs.existsSync(root+'/cosign-private'),false);
const negatives=[];
for(const [name,fn]of [['approval-write',()=>fs.writeFileSync(root+'/cosign-approval.json','bad')],['object-write',()=>fs.writeFileSync(a.objects[0].objectPath,'bad')],['public-key-write',()=>fs.writeFileSync(a.trustIdentities[0].publicKeyPath,'bad')],['docker-read',()=>fs.accessSync('/run/docker.sock',fs.constants.R_OK)],['kubeconfig-read',()=>fs.accessSync('/etc/rancher/k3s/k3s.yaml',fs.constants.R_OK)]]){assert.throws(fn);negatives.push({name,classification:'REAL',status:'DENIED'});}
if(process.argv[4]==='tool-missing'){
 await run('actual-local-tool-missing',{status:{cosign:'NOT_CONFIGURED'}});
}else{
const first=await run('A-three-valid');
await run('B-cosign-disabled',{enabled:['gitleaks','semgrep']});
await run('C-semgrep-disabled',{enabled:['gitleaks','cosign']});
await run('D-gitleaks-disabled',{enabled:['semgrep','cosign']});
await run('E-all-disabled',{enabled:[]});
await run('F-cosign-tampered',{object:'tampered',expected:{gitleaks:'PASS',semgrep:'PASS',cosign:'FAIL'}});
await run('G-semgrep-fail',{ssource:'vulnerable',expected:{gitleaks:'PASS',semgrep:'FAIL',cosign:'PASS'}});
await run('H-gitleaks-fail',{gsource:'secret',expected:{gitleaks:'FAIL',semgrep:'PASS',cosign:'PASS'}});
await run('I-cosign-timeout',{cosignTimeout:1,status:{cosign:'ERROR'}});
await run('J-global-off',{mode:'off'});
await run('K-master-off',{master:false});
await run('L-cosign-wrong-trust',{object:'wrong-trust',expected:{gitleaks:'PASS',semgrep:'PASS',cosign:'FAIL'}});
await run('M-cosign-missing-signature',{object:'missing',expected:{gitleaks:'PASS',semgrep:'PASS',cosign:'FAIL'}});
await run('N-cosign-malformed-signature',{object:'malformed',expected:{gitleaks:'PASS',semgrep:'PASS',cosign:'FAIL'}});
await run('O-cosign-unavailable',{caps:{...allCaps,COSIGN_BINARY:{state:'NOT_CONFIGURED'}},status:{cosign:'NOT_CONFIGURED'}});
const other=await run('P-service-project',{project:'service-fixture',profile:'container-service',source:'service-clean'});
assert.notEqual(first.r.gate.cosign.runtimeFacts.trust.publicKeySha256,other.r.gate.cosign.runtimeFacts.trust.publicKeySha256);
await run('Q-cross-project-identity-rejected',{cosignOverride:'service-fixture-valid',status:{cosign:'POLICY_ERROR'}});
const beforeRoute=counts(),router=path.join(out,prefix+'router');fs.mkdirSync(router,{mode:0o700});const args={run:first.r,artifactDirectory:first.dir,expectedSealDigest:first.r.artifact.sealDigest,output:router},ok=routeResults(args),failed=routeResults(args);assert.deepEqual(beforeRoute,counts());assert.equal(ok.receipts[1].deliveryDecision,'DELIVERED_LOCAL_ONLY');assert.equal(failed.receipts[1].deliveryDecision,'ERROR');assert.equal(failed.receipts[0].deliveryDecision,'DRY_RUN');assert.equal(failed.candidateDeliveryAllowed,false);
for(const batch of [ok,failed])for(const receipt of batch.receipts)for(const id of ids)assert.equal(receipt.resultDigests[id],first.r.gate[id].resultDigest);
fs.writeFileSync(path.join(out,prefix+'router-receipts.json'),JSON.stringify({ok,failed,countsBefore:beforeRoute,countsAfter:counts(),policyCounts:first.r.policyEvaluationCounts},null,2),{flag:'wx',mode:0o400});
assert.equal(fs.readdirSync(out).some(x=>/^(?:scan-|semgrep-scan-|cosign-verify-)/.test(x)),false);
}
fs.writeFileSync(path.join(out,prefix+(process.argv[4]==='tool-missing'?'missing-tool-suite.json':'three-real-suite.json')),JSON.stringify({classification:'REAL_CONTROLLED_SAME_ROUND_THREE_NATIVE_TOOLS_NOT_PRODUCTION_RUNTIME',records,negatives,counts:counts(),routerChecks:process.argv[4]==='tool-missing'?0:2,privateKeysAbsentBeforeManager:true,scannedSourceExecuted:false,productionSigning:0,release:0,rollout:0,runtime:'14/16'},null,2),{flag:'wx',mode:0o400});console.log(JSON.stringify({suite:'PASS',cases:records.length,negatives:negatives.length,counts:counts(),routerChecks:process.argv[4]==='tool-missing'?0:2}));
