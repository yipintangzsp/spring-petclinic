// Collected artifacts only. No scanner, Cosign verification or Policy execution.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {verifyArtifact} from '../../../infra/security/manager-v2/result.mjs';import {sha,digest} from '../../../infra/security/summary-v2/codec.mjs';
const root=path.dirname(new URL(import.meta.url).pathname),read=n=>JSON.parse(fs.readFileSync(path.join(root,n))),suite=read('real-linux/outputs/attempt2-three-real-suite.json'),ids=['gitleaks','semgrep','cosign'],records=[];
for(const record of suite.records){
 const dir=path.join(root,'real-linux/outputs',record.name);assert.equal(verifyArtifact(dir,record.artifactSeal),true);const summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json')));
 for(const k of ['managerVersion','validationRunId','projectId','profile','effectiveConfigDigest','policyVersion','pluginResults','overallDecision','blockers'])assert.ok(Object.hasOwn(summary,k));
 assert.equal(summary.managerVersion,'2.0.0-candidate.4');assert.equal(summary.promotion.status,'BLOCKED');assert.equal(summary.productionEvidence,false);
 for(const id of ids){const result=JSON.parse(fs.readFileSync(path.join(dir,id+'.result.json')));assert.deepEqual(result,summary.pluginResults.find(p=>p.pluginId===id));assert.equal(result.resultDigest,record.plugins[id].resultDigest);
  for(const k of ['pluginId','pluginVersion','executionStatus','policyDecision','rawReportDigest','factDigest','resultDigest','evidenceRefs'])assert.ok(Object.hasOwn(result,k));
  if(result.executionStatus==='COMPLETED'){
   const raw=fs.readFileSync(path.join(dir,id+'.raw.json'),'utf8'),fact=JSON.parse(fs.readFileSync(path.join(dir,id+'.facts.json')));assert.equal(sha(raw),result.rawReportDigest);assert.equal(digest(fact),result.factDigest);assert.equal(result.policy.factDigest,result.factDigest);assert.equal(result.evaluationCount,1);assert.equal(result.policy.evaluation.decision,result.oldGateDecision);assert.equal(record.policyCounts[id],1);
   if(id==='cosign'){const r=JSON.parse(raw);assert.deepEqual(fact.raw,r);assert.equal(r.trust.authorizedProject,record.projectId);assert.equal(r.trust.scope,'CONTROLLED_TEST_ONLY_NOT_PRODUCTION');assert.equal(r.command.exitStatus===0,result.policyDecision==='PASS');}
  }else{assert.equal(result.policyDecision,null);assert.equal(result.evaluationCount,0);}
 }
 records.push({name:record.name,projectId:record.projectId,profile:record.profile,plugins:record.plugins,artifactVerified:true,overallStatus:summary.overallStatus});
}
const router=read('real-linux/outputs/attempt2-router-receipts.json');assert.deepEqual(router.countsBefore,router.countsAfter);assert.deepEqual(router.policyCounts,{cosign:1,gitleaks:1,semgrep:1});
for(const batch of [router.ok,router.failed])for(const receipt of batch.receipts)for(const id of ids)assert.equal(receipt.resultDigests[id],suite.records[0].plugins[id].resultDigest);
const missing=read('actual-missing-tool-execution.json');assert.equal(missing.exit,0);assert.equal(missing.temporaryDomainRemoved,true);const m=JSON.parse(missing.stdout);assert.equal(m.result.executionStatus,'NOT_CONFIGURED');assert.equal(m.result.policyDecision,null);assert.deepEqual(m.countsBefore,m.countsAfter);
const receipts={classification:'VERIFICATION_OF_REAL_COLLECTED_BYTES_NOT_REEXECUTION',mainSuiteCases:records.length,permissionNegatives:suite.negatives.length,routerTests:2,counts:suite.counts,records,actualMissingTool:{status:'VERIFIED',scope:'separate real filesystem prerequisite only; no native tool run',counts:m.countsAfter},policySingleEvaluation:true,resultDigestReuse:true,rawFactsPreserved:true,promotion:'BLOCKED',runtime:'14/16',release:0,rollout:0};
fs.writeFileSync(path.join(root,'execution-verification.json'),JSON.stringify(receipts,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({cases:records.length,actualMissingTool:'VERIFIED_PREREQUISITE_ONLY',counts:suite.counts,status:'PASS'}));
