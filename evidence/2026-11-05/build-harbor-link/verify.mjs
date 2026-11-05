// Offline verification of existing signed evidence. No scan, Policy evaluation or registry write.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {verifyEnvelope,validate} from '../../../infra/security/provenance/contract.mjs';
import {validateBuildStatement} from '../../../infra/security/provenance/build-contract.mjs';
const dir=new URL('./',import.meta.url),read=n=>JSON.parse(fs.readFileSync(new URL(n,dir)));
const s=read('sources.json'),p=read('archived-proof.json');
const commit=s.securityBuild.commit,image=s.summary.auditTargetImage,digest=image.split('@')[1];
const builder=s.builderReports.find(x=>x.path.endsWith('/build-provenance.json')).body;
const meta=s.builderReports.find(x=>x.path.endsWith('/image-build-metadata.json')).body;
const validation=s.securityReports.find(x=>x.path.endsWith('/provenance.json')).body;
const oldVerification=s.securityReports.find(x=>x.path.endsWith('/build-attestation-verification.json')).body;
const manager=s.securityReports.find(x=>x.path.endsWith('/security-manager.json')).body;
assert.equal(s.securityBuild.number,270);assert.equal(s.securityBuild.result,'SUCCESS');
assert.equal(s.summary.build,270);assert.equal(s.summary.source,commit);assert.equal(s.summary.build_result,'SUCCESS');
assert.equal(s.summary.securityMode,'enforce');assert.equal(s.summary.gitleaks_status,'success');assert.equal(s.summary.gitleaks_findings,0);
assert.equal(manager.mode,'enforce');assert.ok(manager.modules.every(x=>x.status==='success'&&(x.exitCode===undefined||x.exitCode===0)));
assert.ok(p.gateStage.completed&&!p.gateStage.errorOnStart&&!p.gateStage.errorOnEnd);assert.equal(p.totalErrorNodes,0);
assert.equal(validation.buildNumber,270);assert.equal(validation.commit,commit);assert.equal(validation.candidateImage,image);
assert.equal(s.candidateBuild.number,2);assert.equal(s.candidateBuild.result,'SUCCESS');assert.equal(s.candidateBuild.commit,commit);
assert.equal(builder.source.commit,commit);assert.equal(builder.builder.buildNumber,2);assert.equal(builder.candidateImage,image);
assert.equal(meta['containerimage.digest'],digest);assert.equal(builder.buildkit.outputDigest,digest);
assert.equal(builder.buildkit.metadataSha256,p.metadataSha256);
for(const arch of ['amd64','arm64'])assert.equal(meta['buildx.build.provenance/linux/'+arch].invocation.parameters.root.request.args['vcs:revision'],commit);
assert.equal(oldVerification.status,'success');assert.equal(oldVerification.expected.commit,commit);assert.equal(oldVerification.expected.image,image);
assert.equal(String(oldVerification.expected.buildNumber),'2');assert.equal(s.harbor.http,200);assert.equal(s.harbor.digest,digest);
assert.equal(s.harbor.type,'IMAGE');assert.ok(s.harbor.tags.some(t=>t.name==='0.10.0-ci-1000002'));
assert.ok(meta['image.name'].endsWith(':0.10.0-ci-1000002'));
// Public trust anchor from the exact historical source commit; never read signing private material.
const key=execFileSync('git',['show',commit+':infra/security/cosign.pub'],{maxBuffer:8192});
assert.deepEqual(key,fs.readFileSync(new URL('../../../infra/security/cosign.pub',dir)));
const envelopes=n=>{
 const text=Buffer.from(p.files[n],'base64').toString('utf8');
 try{const x=JSON.parse(text);return Array.isArray(x)?x:[x];}catch{return text.trim().split('\n').map(JSON.parse);}
};
const statements=envelopes('.devsecops/build-attestation-envelope.json').map(e=>verifyEnvelope(e,key));
const expected=oldVerification.expected;
const actual=statements.find(st=>{try{validateBuildStatement(st,expected);return true;}catch{return false;}});
assert.ok(actual);assert.deepEqual(actual.predicate,builder);
const validated=envelopes('.devsecops/attestation-envelope.json').map(e=>verifyEnvelope(e,key)).find(st=>{
 try{validate(st,{...validation,image});return true;}catch{return false;}
});assert.ok(validated);
// These reject cross-build/cross-digest joins, without evaluating any security policy again.
assert.throws(()=>validateBuildStatement(actual,{...expected,commit:'0'.repeat(40)}));
assert.throws(()=>validateBuildStatement(actual,{...expected,image:image.replace(digest,'sha256:'+'0'.repeat(64))}));
const proof={observedAt:s.observedAt,classification:'HISTORICAL',
 commit,commitBuildGateLink:'VERIFIED',buildImageDigestLink:'VERIFIED',
 securityBuild:{...s.securityBuild,gate:'PASS',mode:'enforce',gateEvidence:p.gateStage,source:s.summary.source,
 summaryRecordedAt:s.summary.recorded_at,summarySha256:s.summarySha256,auditTargetImage:image,gitleaksFindings:0},
 imageBuild:{...s.candidateBuild,buildType:builder.buildType,startedAt:builder.startedAt,completedAt:builder.finishedAt,
 signedBuildStatementVerified:true,buildMetadataSha256:p.metadataSha256},
 harbor:{...s.harbor,source:'LIVE_QUERY',queryObservedAt:s.observedAt,repository:'petclinic/petclinic',tag:'0.10.0-ci-1000002',
 uiUrl:'http://harbor.devops.local/harbor/projects',apiUrl:'http://harbor.devops.local/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+digest},
 signedSecurityValidationVerified:true,publicKeySha256:crypto.createHash('sha256').update(key).digest('hex'),
 binding:'Two explicitly separate historical jobs linked by signed build provenance and #270 exact auditTargetImage; not one image-producing job.',
 exclusions:['Not security-gitlab-push-demo #4','Not the current deployed runtimeImage','No V2 Runtime 16/16 claim'],
 negativeChecks:{wrongCommit:'REJECTED',wrongDigest:'REJECTED'},newBuildRequired:false,releaseCount:0,rolloutCount:0};
fs.writeFileSync(new URL('verified.json',dir),JSON.stringify(proof,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({commit,securityBuild:proof.securityBuild.url,imageBuild:proof.imageBuild.url,gate:proof.securityBuild.gate,
 tag:proof.harbor.tag,digest,signedStatementsVerified:true,newBuildRequired:false}));
