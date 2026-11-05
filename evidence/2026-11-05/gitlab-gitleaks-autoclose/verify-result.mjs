import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {verifyArtifact,verifyResult} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const out=path.dirname(new URL(import.meta.url).pathname), read=n=>JSON.parse(fs.readFileSync(path.join(out,n)));
const observed=read('observed-redelivery.json'),archived=read('build-artifacts.json');
const files=Object.fromEntries(Object.entries(archived.files).map(([n,v])=>[n,Buffer.from(v,'base64')]));
const receipt=JSON.parse(files['evidence/jenkins-gitleaks-receipt.json']);
const {receiptDigest,...body}=receipt;assert.equal(digest(body),receiptDigest);
const dir=path.join(out,'archived-artifact');fs.mkdirSync(dir,{mode:0o700});
for(const [n,b]of Object.entries(files)){
 assert.match(n,/^evidence\/(artifact\/)?[-a-zA-Z0-9_.]+\.json$/);
 if(n.startsWith('evidence/artifact/'))fs.writeFileSync(path.join(dir,path.basename(n)),b,{flag:'wx',mode:0o400});
}
assert.equal(verifyArtifact(dir,receipt.artifactDigest),true);
const parse=n=>JSON.parse(files['evidence/artifact/'+n]);
const result=parse('gitleaks.result.json'),runtime=parse('gitleaks.runtime-facts.json'),facts=parse('gitleaks.facts.json');
verifyResult(result);assert.equal(receipt.resultDigest,result.resultDigest);
assert.equal(receipt.rawReportDigest,sha(files['evidence/artifact/gitleaks.raw.json']));
assert.equal(receipt.factDigest,digest(facts));assert.deepEqual(runtime,result.runtimeFacts);
assert.deepEqual(parse('gitleaks.raw.json'),[]);
assert.equal(result.evaluationCount,1);assert.equal(result.policyDecision,'PASS');assert.equal(result.oldGateDecision,'PASS');
assert.equal(runtime.identity.uid,24021);assert.equal(runtime.identity.gid,24021);
assert.deepEqual(runtime.identity.groups,[24021]);assert.equal(runtime.identity.noNewPrivs,true);
assert.equal(runtime.identity.dockerSocketReadable,false);assert.equal(runtime.identity.kubeconfigReadable,false);
assert.equal(runtime.tool.version,'8.30.1');assert.equal(runtime.command.exitStatus,0);
assert.equal(receipt.cleanup,'VERIFIED');assert.equal(receipt.classification,'REAL_CONTROLLED_EXECUTION');
assert.equal(observed.build.result,'SUCCESS');assert.equal(receipt.build,4);
assert.equal(observed.build.cause.after,receipt.commit);assert.equal(receipt.commit,'d21b1271982bd4d8d90857b889c312d522779fc2');
assert.deepEqual(observed.build.causes,['com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause']);
assert.ok(observed.build.console.includes('Demo Publish reached; no image, GitOps or deployment action'));
const deliveries=observed.deliveries.filter(x=>x.after===receipt.commit);
assert.equal(deliveries.length,2);assert.ok(deliveries.every(x=>x.httpStatus==='200'));
const health=read('production-health.json');assert.equal(health.ready,3);assert.equal(health.http,200);
assert.ok(Object.values(health.nodes).every(v=>v==='True'));
assert.equal(health.argoSync,'Synced');assert.equal(health.argoHealth,'Healthy');assert.equal(health.dockerSocketMode,'0660');
assert.equal(health.generation,175);assert.deepEqual(health.images,['core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137']);
assert.equal(observed.productionJob.lastBuild,270);assert.equal(observed.productionJob.result,'SUCCESS');
assert.equal(observed.productionJob.definitionSha256,'abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25');
assert.equal(observed.productionJob.summarySha256,'ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8');
const proof={classification:'HISTORICAL',executionClassification:'REAL_CONTROLLED_EXECUTION',observedAt:observed.observedAt,
 commit:receipt.commit,branch:receipt.branch,buildUrl:observed.build.url,build:4,jenkinsResult:'SUCCESS',
 triggerMode:'REAL_GITLAB_STORED_EVENT_REDELIVERY',deliveries,initialBuild:3,initialBuildResult:'FAILURE',
 initialFailure:'Packaging accidentally included local opt-in config; scan was not started. Fixed by packaging infra-only dependencies.',
 pushCount:1,jenkinsBuildApiCalled:false,...receipt,rawFactsUnchanged:true,artifactVerified:true,
 productionHealth:health,productionJob:observed.productionJob,productionSecurityManager:'NOT_ACTIVE',canonicalRuntime:'14/16',originalEvidenceIntegrity:'FAILED'};
fs.writeFileSync(path.join(out,'verified.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({runId:receipt.runId,exit:runtime.command.exitStatus,findings:receipt.findingsCount,
 policy:result.policyDecision,evaluations:result.evaluationCount,resultDigest:result.resultDigest,
 rawReportDigest:result.rawReportDigest,artifactVerified:true,production:'HEALTHY'}));
