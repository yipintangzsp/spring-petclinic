// Verify collected bytes/results only. No scanner or Policy evaluation is called.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {verifyArtifact} from '../../../infra/security/manager-v2/result.mjs';import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const root=path.dirname(new URL(import.meta.url).pathname),read=p=>JSON.parse(fs.readFileSync(path.join(root,p))),suite=read('real-linux/outputs/attempt3-real-suite.json');
const verified=[];
for(const r of suite.records){
 const dir=path.join(root,'real-linux/outputs',r.name);assert.equal(verifyArtifact(dir,r.sealDigest),true);const summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json')));
 assert.equal(summary.managerVersion,'2.0.0-candidate.3');assert.equal(summary.promotion.status,'BLOCKED');assert.equal(summary.productionEvidence,false);assert.equal(summary.effectiveProfile,r.profile);
 for(const id of ['gitleaks','semgrep']){
  const result=JSON.parse(fs.readFileSync(path.join(dir,id+'.result.json')));assert.deepEqual(result,summary.pluginResults.find(p=>p.pluginId===id));assert.equal(result.resultDigest,r.plugins[id].resultDigest);
  for(const k of ['managerVersion','runId','projectId','effectiveProfile','policyVersion','securityEnabled','globalMode','securityLevel','pluginId','pluginVersion','executionStatus','policyDecision','rawReportDigest','factDigest','resultDigest','evidenceRefs'])assert.ok(Object.hasOwn(result,k),r.name+' missing '+k);
  if(result.executionStatus==='COMPLETED'){
   const bytes=fs.readFileSync(path.join(dir,id+'.raw.json'),'utf8'),facts=JSON.parse(fs.readFileSync(path.join(dir,id+'.facts.json')));assert.equal(sha(bytes),result.rawReportDigest);assert.equal(digest(facts),result.factDigest);assert.equal(result.policy.factDigest,result.factDigest);assert.equal(result.evaluationCount,1);assert.equal(result.oldGateDecision,result.policyDecision);
   if(id==='semgrep'){const raw=JSON.parse(bytes);assert.deepEqual(raw.reports,raw.nativeReportTexts.map(x=>{assert.equal(sha(x.bytesUtf8),x.sha256);return JSON.parse(x.bytesUtf8);}));assert.deepEqual(facts.raw.findings,raw.reports.flatMap(x=>x.results));}
  }else{assert.equal(result.policyDecision,null);assert.equal(result.evaluationCount,0);}
 }
 verified.push({name:r.name,overallStatus:summary.overallStatus,plugins:r.plugins,artifactVerified:true,schemaFieldsPresent:true});
}
const route=read('real-linux/outputs/attempt3-router-receipts.json');assert.deepEqual(route.countsBefore,route.countsAfter);assert.deepEqual(route.policyEvaluationCounts,{gitleaks:1,semgrep:1});
for(const batch of [route.delivered,route.failed])for(const receipt of batch.receipts)for(const id of ['gitleaks','semgrep'])assert.equal(receipt.resultDigests[id],suite.records[0].plugins[id].resultDigest);
const out={classification:'COLLECTED_REAL_EXECUTION_ARTIFACT_VERIFICATION_NO_REEXECUTION',realControlledCases:verified.length,securityBoundaryChecks:suite.securityBoundaryChecks.length,routerDeliveryChecks:2,finalSuccessfulRoundCounts:suite.counts,records:verified,sourceRawFactsPreserved:true,policySingleEvaluation:true,resultDigestReuse:true,promotion:'BLOCKED',runtime:'14/16',release:0,rollout:0};
fs.writeFileSync(path.join(root,'execution-verification.json'),JSON.stringify(out,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({cases:verified.length,securityBoundaryChecks:suite.securityBoundaryChecks.length,routerChecks:2,counts:suite.counts,status:'PASS'}));
