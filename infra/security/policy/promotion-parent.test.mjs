import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import crypto from 'node:crypto';
import {evaluate} from './engine.mjs';import {replayPromotion} from './promotion-replay.mjs';import {base,fixture,read,sha,gateChange,approvalChange,pub} from './promotion-fixtures.mjs';
const records=[];
function run(stage,name,change,want,branch){test(stage+' original Promotion '+name,async()=>{
 const input=fixture(stage);change(input);const before=JSON.stringify(input),raw=await replayPromotion(input),old=raw.execution.exitStatus===0?'PASS':'FAIL',p=evaluate({component:'security-approval-promotion',status:'success',raw});assert.equal(old,want,raw.execution.diagnostic);assert.equal(p.decision,old);assert.equal(p.securityLevel,'standard');assert.equal(JSON.stringify(input),before);assert.deepEqual(p.rawEvidence,raw);
 const file=stage+'--'+name+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify({input,raw},null,2));records.push({stage,name,branch,classification:'CONTROLLED_REPLAY',oldDecision:old,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),rawSha256:sha(JSON.stringify(raw)),fixture:file,diagnostic:raw.execution.diagnostic});
});}
for(const stage of ['candidate-sbom','sign-approve','dry-run','deploy','private-main'])run(stage,'valid',()=>{},'PASS','positive');
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({records},null,2)));
for(const stage of ['sign-approve','dry-run','deploy']){
 run(stage,'security-gate-not-SUCCESS',r=>r.environment.SECURITY_GATE_RESULT='FAILURE','FAIL','eligibility');
 run(stage,'build-mismatch-summary',r=>gateChange(r,'summary',p=>p.build=259),'FAIL','build');
 run(stage,'source-mismatch-summary',r=>gateChange(r,'summary',p=>p.source='b'.repeat(40)),'FAIL','source');
 run(stage,'summary-missing',r=>r.fileErrors['.devsecops/security-summary.json']='ENOENT','FAIL','missing');
 run(stage,'summary-malformed',r=>r.files['.devsecops/security-summary.json']='{','FAIL','malformed');
 run(stage,'candidate-not-fixed-digest',r=>r.environment.AUDIT_CANDIDATE_IMAGE='core.harbor.domain/petclinic/petclinic:latest','FAIL','digest');
 run(stage,'candidate-digest-mismatch',r=>r.environment.AUDIT_CANDIDATE_IMAGE=r.environment.AUDIT_CANDIDATE_IMAGE.slice(0,-1)+'0','FAIL','digest');
 run(stage,'foreign-heavy-Lease',r=>r.runtime.leaseOwned=false,'FAIL','prerequisite');
 for(const sev of ['trivy_critical','trivy_high'])run(stage,sev+'-security-ineligible',r=>gateChange(r,'summary',p=>p[sev]=1),'FAIL','eligibility');
 run(stage,'Trivy-incomplete-dual-arch',r=>gateChange(r,'trivy',p=>p.scans.pop()),'FAIL','eligibility');
 run(stage,'Trivy-foreign-target',r=>gateChange(r,'trivy',p=>p.targetScope='live'),'FAIL','digest');
 run(stage,'business-mutated',r=>gateChange(r,'business',p=>p.unchanged=false),'FAIL','eligibility');
 for(const name of ['sourceScan','admission','semgrep','zap','falco','dojo','kubescape']){
  run(stage,name+'-failed',r=>gateChange(r,name,p=>p.status='failed'),'FAIL','eligibility');
  run(stage,name+'-foreign-source',r=>gateChange(r,name,p=>p.source='b'.repeat(40)),'FAIL','source');
 }
 run(stage,'candidate-SBOM-digest-mismatch',r=>gateChange(r,'sbom',p=>p.candidate+='0'),'FAIL','digest');
 run(stage,'candidate-SBOM-one-platform',r=>gateChange(r,'sbom',p=>p.architectures.pop()),'FAIL','eligibility');
 run(stage,'candidate-SBOM-duplicate-platform',r=>gateChange(r,'sbom',p=>p.architectures[1].arch=p.architectures[0].arch),'FAIL','eligibility');
 run(stage,'candidate-SBOM-invalid-hash',r=>gateChange(r,'sbom',p=>p.architectures[0].sbomSha256='wrong'),'FAIL','eligibility');
 run(stage,'source-identity-not-fixed',r=>r.files['.git-sha']='main','FAIL','source');
}
for(const k of ['create','copy','remove','unzip'])run('candidate-sbom','Docker-or-extract-'+k+'-failure',r=>r.candidate[k]=false,'FAIL','execution');
run('candidate-sbom','not-pinned-candidate',r=>r.environment.AUDIT_CANDIDATE_IMAGE='registry/app:latest','FAIL','digest');
run('candidate-sbom','invalid-CycloneDX',r=>r.candidate.bom={bomFormat:'SPDX',components:[{}]},'FAIL','malformed');
run('candidate-sbom','empty-component-inventory',r=>r.candidate.bom.components=[],'FAIL','missing');
for(const stage of ['dry-run','deploy']){
 run(stage,'approval-missing',r=>r.fileErrors['.devsecops/approved-release.json']='ENOENT','FAIL','missing-approval');
 run(stage,'approval-malformed',r=>r.files['.devsecops/approved-release.json']='{','FAIL','malformed');
 for(const [key,value,branch]of [['jenkinsBuild',259,'build'],['securitySourceCommit','b'.repeat(40),'source'],['candidateImage','core.harbor.domain/petclinic/petclinic@sha256:'+'0'.repeat(64),'digest'],['status','PENDING','approval-state'],['securityGate','FAILURE','eligibility'],['approvedDigest','sha256:'+'0'.repeat(64),'digest'],['candidateDigest','sha256:'+'0'.repeat(64),'digest']])run(stage,'approval-'+key+'-mismatch',r=>approvalChange(r,p=>p[key]=value),'FAIL',branch);
 run(stage,'approval-signature-invalid',r=>r.cosign.verifyBlob=false,'FAIL','signature');
 run(stage,'approval-signing-incomplete',r=>{const p=JSON.parse(r.files['.devsecops/approval-signing.json']);p.status='failed';r.files['.devsecops/approval-signing.json']=JSON.stringify(p);},'FAIL','signature');
 run(stage,'approval-private-files-not-removed',r=>{const p=JSON.parse(r.files['.devsecops/approval-signing.json']);p.temporaryPrivateFilesRemoved=false;r.files['.devsecops/approval-signing.json']=JSON.stringify(p);},'FAIL','signature');
 run(stage,'Argo-repository-foreign',r=>r.app.repo='https://example.invalid/other.git','FAIL','identity');
 run(stage,'Argo-target-foreign',r=>r.app.target='other-branch','FAIL','identity');
 run(stage,'GitOps-runtime-moved',r=>r.git.manifest=r.git.manifest.replace(r.approval.previousRuntimeImage,r.approval.candidateImage),'FAIL','concurrency');
 run(stage,'GitOps-duplicate-image',r=>r.git.manifest+='image: '+r.approval.previousRuntimeImage+'\n','FAIL','identity');
 run(stage,'GitOps-remote-concurrent-update',r=>r.git.remoteSame=false,'FAIL','concurrency');
 run(stage,'no-scoped-Git-credential',r=>delete r.environment.GITLAB_TOKEN,'FAIL','prerequisite');
 run(stage,'empty-change-no-new-release',r=>r.git.patch='','FAIL','concurrency');
 run(stage,'old-createdAt-no-new-expiration-policy',r=>approvalChange(r,p=>p.createdAt='2000-01-01T00:00:00Z'),'PASS','existing-no-age-expiration');
 run(stage,'approval-provenance-not-added-requirement',r=>approvalChange(r,p=>{p.provenance={status:'not_configured'};}),'PASS','existing-no-provenance-rule');
 for(const verb of ['clone','diff','ls-remote'])run(stage,'Git-'+verb+'-failure',r=>r.git.fail=[verb],'FAIL','execution');
}
for(const k of ['keyMatches','sign','verify','digestMatches','signBlob','verifyBlob'])run('sign-approve','Cosign-'+k+'-failure',r=>r.cosign[k]=false,'FAIL','signature');
run('sign-approve','decryption-unavailable',r=>r.decrypt.status=1,'FAIL','prerequisite');
run('sign-approve','decryption-malformed-JSON',r=>r.decrypt.stdout='{','FAIL','malformed');
run('sign-approve','decrypted-key-missing',r=>r.decrypt.stdout=JSON.stringify({data:{}}),'FAIL','missing');
run('sign-approve','Cosign-empty-claim',r=>r.cosign.rawVerify='[]','FAIL','signature');
run('sign-approve','Cosign-malformed-claim',r=>r.cosign.rawVerify='{','FAIL','malformed');
run('sign-approve','Cosign-null-claim',r=>r.cosign.rawVerify='null','FAIL','malformed');
run('sign-approve','tool-hash-changed',r=>r.runtime.tools.cosign.sha256='wrong','FAIL','prerequisite');
for(const stage of ['candidate-sbom','sign-approve','dry-run','deploy','private-main']){
 run(stage,'scanner-manifest-hash-mismatch',r=>r.runtime.expectedManifestSha256='wrong','FAIL','prerequisite');
 for(const key of ['temp-create','temp-remove'])run(stage,'IO-'+key,r=>r.io[key]='EACCES','FAIL','io');
}
for(const key of ['temp-chmod','write:/tmp/promotion-frozen/key','mkdir:/tmp/promotion-frozen/docker','write:/tmp/promotion-frozen/docker/config.json','write:.devsecops/approved-release.pending.json','write:.devsecops/approval-signing.json','rename:.devsecops/approved-release.json','rename:.devsecops/approved-release.sig'])run('sign-approve','IO-'+key.replaceAll('/','_'),r=>r.io[key]='ENOSPC','FAIL','io');
run('sign-approve','cleanup-existence-false-only-is-nonblocking',r=>r.tempExists=true,'PASS','existing-cleanup-flag');
for(const stage of ['dry-run','deploy'])for(const key of ['write:.devsecops/promotion-dry-run.patch','write:.devsecops/promotion-dry-run.json','write:.devsecops/promotion-result.json','write:/tmp/promotion-frozen/repo/k8s/production/petclinic.yaml'])run(stage,'IO-'+key.replaceAll('/','_'),r=>r.io[key]='ENOSPC','FAIL','io');
for(const verb of ['commit','push'])run('deploy','Git-'+verb+'-failure',r=>r.git.fail=[verb],'FAIL','execution');
run('deploy','rollout-fails-rollback-converges',r=>{r.app.converged=false;r.clockStep=100000;},'FAIL','rollback');
run('deploy','rollout-and-rollback-fail',r=>{r.app.converged=false;r.app.rollbackConverged=false;r.clockStep=100000;},'FAIL','rollback');
run('deploy','concurrent-release-blocks-rollback',r=>{r.app.converged=false;r.git.rollbackSame=false;r.clockStep=100000;},'FAIL','rollback');
run('deploy','Argo-UID-replaced',r=>r.app.identitySame=false,'FAIL','identity');
run('deploy','health-not-UP',r=>{r.app.health='DOWN';r.clockStep=100000;},'FAIL','infrastructure');
run('deploy','HTTP-not-200',r=>{r.app.http=503;r.clockStep=100000;},'FAIL','infrastructure');
run('deploy','HTTP-transport-error',r=>r.app.httpError=true,'FAIL','infrastructure');
run('deploy','Pods-not-Ready',r=>{r.app.podsReady=false;r.clockStep=100000;},'FAIL','infrastructure');
for(const verb of ['fetch','checkout','commit','push'])run('private-main','Git-'+verb+'-failure',r=>r.git.fail=[verb],'FAIL','execution');
run('private-main','source-main-concurrent-change',r=>r.git.rollbackSame=false,'FAIL','concurrency');
run('private-main','scanned-digest-mismatch',r=>{const p=JSON.parse(r.files['target/platform/harbor.json']);p.digest='sha256:'+'0'.repeat(64);r.files['target/platform/harbor.json']=JSON.stringify(p);},'FAIL','digest');
run('private-main','unsigned-release-proof',r=>{const p=JSON.parse(r.files['.devsecops/release-evidence.json']);p.signed=false;r.files['.devsecops/release-evidence.json']=JSON.stringify(p);},'FAIL','signature');
run('private-main','release-tag-build-mismatch',r=>r.environment.IMAGE_TAG='0.10.0-ci-259','FAIL','build');
run('private-main','wrong-release-source',r=>{const p=JSON.parse(r.files['.devsecops/signing-release.json']);p.source='b'.repeat(40);r.files['.devsecops/signing-release.json']=JSON.stringify(p);},'FAIL','source');
for(const build of [259,260])test('historical real approval '+build,()=>{
 const approvalBytes=fs.readFileSync(base+'historical/'+build+'/approved-release.json'),approval=JSON.parse(approvalBytes),sig=Buffer.from(fs.readFileSync(base+'historical/'+build+'/approved-release.sig','utf8').trim(),'base64');assert.equal(crypto.verify('sha256',approvalBytes,pub,sig),true,'Original historic approval blob signature');
 const result=read(base+'historical/'+build+'/promotion-result.json'),signing=read(base+'historical/'+build+'/approval-signing.json'),stage=result.mode==='dry-run'?'dry-run':'deploy';assert.equal(approval.approvedDigest,approval.candidateDigest);assert.equal(signing.status,'success');const raw={schema:1,stage,complete:true,classification:'REAL_HISTORICAL',execution:{exitStatus:0},inputIdentity:{build:approval.jenkinsBuild,source:approval.securitySourceCommit,candidate:approval.candidateImage,approvedDigest:approval.approvedDigest},observations:[{type:'historical-result',promotionResult:result.promotionResult,signatureLocallyReverified:true}],reports:{'.devsecops/promotion-result.json':JSON.stringify(result)}},before=JSON.stringify(raw),old=['DRY_RUN_PASS','DEPLOYED'].includes(result.promotionResult)?'PASS':'FAIL',p=evaluate({component:'security-approval-promotion',status:'success',raw});assert.equal(old,'PASS');assert.equal(p.decision,old);assert.deepEqual(p.rawEvidence,raw);const file='historical--'+build+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify(raw,null,2));records.push({stage,name:'historical-'+build,branch:'historical',classification:'REAL_HISTORICAL',oldDecision:old,standardDecision:p.decision,rawPreserved:true,rawSha256:sha(before),fixture:file});
});
for(const [name,change]of [['missing-completeness',r=>r.complete=false],['missing-exit-status',r=>delete r.execution.exitStatus],['successful-result-unavailable',r=>r.reports={}],['unsupported-stage',r=>r.stage='other']])test('incomplete Promotion evidence '+name,async()=>{const raw=await replayPromotion(fixture('dry-run'));change(raw);const p=evaluate({component:'security-approval-promotion',status:'success',raw});assert.equal(p.status,'NOT_TESTED');assert.equal(p.decision,null);});
test('circular self-approval check: Policy performs reads only',async()=>{
 const raw=await replayPromotion(fixture('dry-run')),before=JSON.stringify(raw);const original={write:fs.writeFileSync,rename:fs.renameSync,copy:fs.copyFileSync};let writes=0;
 try{fs.writeFileSync=()=>{writes++;throw Error('Policy write forbidden');};fs.renameSync=()=>{writes++;throw Error('Policy rename forbidden');};fs.copyFileSync=()=>{writes++;throw Error('Policy copy forbidden');};assert.equal(evaluate({component:'security-approval-promotion',status:'success',raw}).decision,'PASS');}finally{fs.writeFileSync=original.write;fs.renameSync=original.rename;fs.copyFileSync=original.copy;}
 assert.equal(writes,0);assert.equal(JSON.stringify(raw),before);const module=fs.readFileSync('infra/security/policy/promotion-evidence.mjs','utf8');assert.ok(!/from ['"].*(?:replay|contract|child_process)/.test(module));assert.ok(!/approvedRelease\(|sign-blob/.test(module));
});
test('new policy result cannot stand in for original approval facts',()=>{const p=evaluate({component:'security-approval-promotion',status:'success',raw:{schema:1,complete:true,policyDecision:'PASS'}});assert.equal(p.decision,null);assert.equal(p.status,'NOT_TESTED');});
test('low / strict / override / audit do not soften original promotion FAIL',async()=>{const input=fixture('dry-run');input.fileErrors['.devsecops/approved-release.json']='ENOENT';const raw=await replayPromotion(input);for(const config of [{securityLevel:'low'},{securityLevel:'strict'},{mode:'audit',componentOverrides:{'security-approval-promotion':{High:'PASS'}}}])assert.equal(evaluate({component:'security-approval-promotion',status:'success',raw},config).decision,'FAIL');});
test('dry-run never reaches commit, push or rollout in original replay',async()=>{const r=await replayPromotion(fixture('dry-run'));assert.ok(!r.observations.some(x=>x.tool==='git'&&['commit','push'].includes(x.args[0])));assert.ok(!r.observations.some(x=>x.type==='http-health'));});
test('successful rollback remains Gate FAIL and is observable',async()=>{const input=fixture('deploy');input.app.converged=false;input.clockStep=100000;const raw=await replayPromotion(input);assert.equal(raw.execution.exitStatus,1);const report=JSON.parse(raw.reports['.devsecops/promotion-result.json']);assert.equal(report.promotionResult,'ROLLED_BACK');assert.equal(report.rollback,true);});
run('dry-run','invalid-mode-rejected',r=>r.modeOverride='invalid','FAIL','configuration');
run('dry-run','missing-approval-signing-report',r=>r.fileErrors['.devsecops/approval-signing.json']='ENOENT','FAIL','missing');
run('dry-run','malformed-approval-signing-report',r=>r.files['.devsecops/approval-signing.json']='{','FAIL','malformed');
run('dry-run','source-label-of-optional-child-absent-not-new-rule',r=>gateChange(r,'sourceScan',p=>delete p.source),'PASS','existing-optional-source');
run('private-main','missing-Git-credential',r=>delete r.environment.GITLAB_TOKEN,'FAIL','prerequisite');
run('private-main','missing-signing-report',r=>r.fileErrors['.devsecops/signing-release.json']='ENOENT','FAIL','missing');
run('private-main','changed-Git-origin',r=>r.app.repo='https://example.invalid/other.git','FAIL','identity');
for(const input of ['.git-sha','.devsecops/trivy-audit.json','.devsecops/source-gate.json','.devsecops/business-after.json','.devsecops/candidate-sbom.json'])run('dry-run','missing-evidence-'+input.replaceAll('/','_'),r=>r.fileErrors[input]='ENOENT','FAIL','missing');
test('failed approval validation reaches no Git mutation',async()=>{const r=fixture('deploy');approvalChange(r,p=>p.jenkinsBuild=259);const raw=await replayPromotion(r);assert.equal(raw.execution.exitStatus,1);assert.ok(!raw.observations.some(x=>x.tool==='git'));});
test('failed signing cannot finalize approved approval artifact',async()=>{const r=fixture('sign-approve');r.cosign.verifyBlob=false;const raw=await replayPromotion(r);assert.equal(raw.execution.exitStatus,1);assert.equal(Object.hasOwn(raw.reports,'.devsecops/approved-release.json'),false);assert.ok(!raw.observations.some(x=>x.key==='rename:.devsecops/approved-release.json'));});
