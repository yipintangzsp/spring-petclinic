import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {validate,verifyEnvelope} from '../provenance/contract.mjs';
import {evaluate} from './engine.mjs';
import {fixture,oracle,synthetic,expected,archive,historical,predicate,pub,sha,file,response,disposablePublic,signStatement} from './provenance-test-harness.mjs';
const out='evidence/2026-11-01/provenance-parent/',records=[];
function run(action,name,change,want,branch){test(action+' complete Provenance '+name,async()=>{
 const raw=fixture(action);change(raw);const before=JSON.stringify(raw),old=await oracle(raw),p=evaluate({component:'provenance',status:'success',raw});
 assert.equal(old.decision,want,'legacy: '+old.reason);assert.equal(p.decision,old.decision,'policy: '+p.reason);assert.equal(p.securityLevel,'standard');assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);assert.deepEqual(JSON.parse(JSON.stringify(p.trace)),JSON.parse(JSON.stringify(old.trace)));
 if(p.decision==='PASS'){
  if(action==='generate')assert.deepEqual(JSON.parse(JSON.stringify(p.generated)),JSON.parse(old.writes['.devsecops/provenance.json']));
  else assert.deepEqual(p.report,JSON.parse(old.writes[action==='verify'?'.devsecops/attestation-verification.json':'.devsecops/attestation-create.json']));
 }
 records.push({action,name,branch,classification:raw.classification,artifactOrigin:raw.artifactOrigin,oldDecision:old.decision,standardDecision:p.decision,rawPreserved:true,externalTraceIdentical:true,inputSha256:sha(before),legacyReason:old.reason,policyReason:p.reason,selectedIndex:p.normalizedFacts.selectedIndex,verificationAttempts:p.normalizedFacts.verificationAttempts});
 fs.writeFileSync(out+'fixtures/'+action+'--'+name+'.json',JSON.stringify(raw,null,2));
});}
for(const action of ['generate','create','verify']){
 run(action,'valid',()=>{},'PASS','positive');
 run(action,'output-directory-denied',r=>r.io['output-mkdir']={error:'read-only output'},'FAIL','io');
 run(action,'runtime-manifest-unreadable',r=>r.runtime.manifestReadError='read denied','FAIL','prerequisite');
 run(action,'runtime-lock-unreadable',r=>r.runtime.lockReadError='read denied','FAIL','prerequisite');
 run(action,'runtime-manifest-malformed',r=>r.runtime.manifest='{','FAIL','prerequisite');
 run(action,'runtime-manifest-hash-mismatch',r=>r.runtime.expectedManifestSha256='wrong','FAIL','prerequisite');
 if(action!=='create'){
  run(action,'candidate-tag',r=>r.environment.PROVENANCE_CANDIDATE='core.harbor.domain/app:latest','FAIL','reference');
  run(action,'candidate-missing',r=>delete r.environment.PROVENANCE_CANDIDATE,'FAIL','reference');
  run(action,'candidate-other-registry',r=>r.environment.PROVENANCE_CANDIDATE='elsewhere.example/app@sha256:'+'a'.repeat(64),'FAIL','reference');
  run(action,'checkout-read-failure',r=>r.files['.git-sha']={error:'read denied'},'FAIL','io');
  run(action,'checkout-commit-env-mismatch',r=>r.environment.PROVENANCE_COMMIT='b'.repeat(40),'FAIL','source');
  run(action,'checkout-commit-not-fixed',r=>{r.files['.git-sha']=file('main');r.environment.PROVENANCE_COMMIT='main';},'FAIL','source');
 }
 if(action!=='generate'){
  run(action,'cosign-tool-mismatch',r=>r.runtime.tools.cosign.sha256='bad','FAIL','prerequisite');
  run(action,'cosign-tool-read-error',r=>r.runtime.tools.cosign={error:'absent'},'FAIL','infrastructure');
 }
}
for(const k of ['PROVENANCE_REPOSITORY','JENKINS_URL'])run('generate','missing-'+k,r=>delete r.environment[k],'FAIL','identity');
run('generate','build-not-integer',r=>r.environment.BUILD_NUMBER='270.5','FAIL','identity');
run('generate','provenance-report-write-denied',r=>r.io['provenance-write']={error:'write denied'},'FAIL','io');
run('generate','missing-JOB_NAME-existing-generation-behavior',r=>delete r.environment.JOB_NAME,'PASS','existing-generation-semantics');
for(const key of ['key-temp-create','key-temp-chmod','key-write','docker-mkdir','docker-write','create-report-write','key-temp-remove'])run('create','IO-'+key,r=>r.io[key]={error:'denied'},'FAIL','io');
run('create','lease-other-holder',r=>r.runtime.lease=response({spec:{holderIdentity:'another'}}),'FAIL','prerequisite');
run('create','lease-query-failed',r=>r.runtime.lease=response('',1),'FAIL','infrastructure');
run('create','lease-query-malformed',r=>r.runtime.lease=response('{'),'FAIL','prerequisite');
run('create','explicit-lease-holder',r=>{r.environment.HEAVY_HOLDER='controlled';r.runtime.lease=response({spec:{holderIdentity:'controlled'}});},'PASS','prerequisite');
run('create','sops-tool-mismatch',r=>r.runtime.tools.sops.sha256='bad','FAIL','prerequisite');
for(const verb of ['sops:decrypt','cosign:attest']){
 run('create',verb+'-nonzero',r=>r.commands[verb][0]=response('suppressed',1),'FAIL','execution');
 run('create',verb+'-timeout',r=>r.commands[verb][0]={status:null,error:'ETIMEDOUT'},'FAIL','infrastructure');
}
run('create','malformed-decrypted-bundle',r=>r.commands['sops:decrypt'][0]=response('{'),'FAIL','prerequisite');
run('create','decrypted-data-missing',r=>r.commands['sops:decrypt'][0]=response({}),'FAIL','prerequisite');
run('create','decrypted-key-missing',r=>r.commands['sops:decrypt'][0]=response({data:{password:'fake'}}),'FAIL','prerequisite');
run('create','decrypted-password-missing-no-new-rule',r=>r.commands['sops:decrypt'][0]=response({data:{privateKey:'SYNTHETIC'}}),'PASS','existing-generation-semantics');
run('create','attest-empty-output-recorded-not-failed',r=>r.commands['cosign:attest'][0]=response(''),'PASS','existing-generation-semantics');
for(const key of ['auth-temp-create','auth-temp-chmod','auth-write','envelope-write','auth-temp-remove','verification-report-write'])run('verify','IO-'+key,r=>r.io[key]={error:'denied'},'FAIL','io');
for(const [name,r]of [['missing-provenance',response('not found',1)],['registry-down',response('unreachable',1)],['registry-unauthorized',response('UNAUTHORIZED',1)],['command-timeout',{status:null,error:'ETIMEDOUT'}],['command-exec-error',{status:null,error:'ENOENT'}],['empty-output',response('')],['malformed-output',response('{')],['empty-attestation-list',response([])],['JSON-null',response('null')],['malformed-envelope',response({})]])run('verify',name,x=>x.commands['cosign:download'][0]=r,'FAIL',name.includes('provenance')?'missing':['empty-output','malformed-output','empty-attestation-list','JSON-null','malformed-envelope'].includes(name)?'malformed':'infrastructure');
run('verify','subject-digest-mismatch',r=>r.environment.PROVENANCE_CANDIDATE=r.environment.PROVENANCE_CANDIDATE.slice(0,-1)+'0','FAIL','digest');
run('verify','candidate-image-name-mismatch',r=>r.environment.PROVENANCE_CANDIDATE=r.environment.PROVENANCE_CANDIDATE.replace('/petclinic@','/another@'),'FAIL','digest');
run('verify','repository-mismatch',r=>r.environment.PROVENANCE_REPOSITORY='http://example.invalid/other.git','FAIL','source');
run('verify','revision-mismatch',r=>{r.environment.PROVENANCE_COMMIT='b'.repeat(40);r.files['.git-sha']=file('b'.repeat(40));},'FAIL','source');
run('verify','builder-URL-mismatch',r=>r.environment.JENKINS_URL='http://other.invalid/','FAIL','builder');
run('verify','pipeline-job-mismatch',r=>r.environment.JOB_NAME='different-job','FAIL','builder');
run('verify','build-number-mismatch',r=>r.environment.BUILD_NUMBER='271','FAIL','identity');
run('verify','public-key-replaced',r=>r.files['infra/security/cosign.pub']=file(disposablePublic),'FAIL','tamper');
run('verify','public-key-read-denied',r=>r.files['infra/security/cosign.pub']={error:'read denied'},'FAIL','io');
run('verify','public-key-malformed',r=>r.files['infra/security/cosign.pub']=file('not a key'),'FAIL','tamper');
run('verify','payload-tampered',r=>{const e=structuredClone(historical);e.payload=Buffer.from('tampered').toString('base64');r.commands['cosign:download'][0]=response(e);},'FAIL','tamper');
run('verify','signature-replaced',r=>{const e=structuredClone(historical);e.signatures=[{sig:'AAAA'}];r.commands['cosign:download'][0]=response(e);},'FAIL','tamper');
for(const [name,change]of [
 ['wrong-predicate-type',s=>s.predicateType='other-type'],['missing-subject',s=>delete s.subject],['two-subjects',s=>s.subject.push(structuredClone(s.subject[0]))],['missing-subject-digest',s=>delete s.subject[0].digest],['signed-wrong-subject',s=>s.subject[0].digest.sha256='a'.repeat(64)],
 ['signed-wrong-repository',s=>s.predicate.repository='other'],['signed-wrong-source',s=>s.predicate.commit='b'.repeat(40)],['signed-wrong-builder',s=>s.predicate.builderIdentity='other'],['signed-wrong-pipeline',s=>s.predicate.pipelineIdentity='other'],['signed-wrong-build',s=>s.predicate.buildNumber=271],['signed-wrong-candidate',s=>s.predicate.candidateImage='other'],['missing-predicate',s=>delete s.predicate],['invalid-timestamp',s=>s.predicate.buildTimestamp='invalid'],['missing-timestamp',s=>delete s.predicate.buildTimestamp],['wrong-build-type',s=>s.predicate.buildType='image-build'],
 ])run('verify',name,r=>synthetic(r,change),'FAIL',name.includes('subject')?'digest':name.includes('source')||name.includes('repository')?'source':name.includes('builder')||name.includes('pipeline')?'builder':'identity');
run('verify','synthetic-valid-no-production-key',r=>synthetic(r,()=>{}),'PASS','positive');
run('verify','valid-stale-timestamp-no-added-freshness-rule',r=>synthetic(r,s=>s.predicate.buildTimestamp='2000-01-01T00:00:00Z'),'PASS','existing-verifier-semantics');
run('verify','subject-name-mismatch-rejected',r=>synthetic(r,s=>s.subject[0].name='unvalidated-name'),'FAIL','digest');
run('verify','zero-commit-negative-control-detects-itself',r=>{synthetic(r,s=>s.predicate.commit='0'.repeat(40));r.files['.git-sha']=file('0'.repeat(40));r.environment.PROVENANCE_COMMIT='0'.repeat(40);},'FAIL','negative-control');
run('verify','verify-has-no-lease-requirement',r=>r.runtime.lease=response('',1),'PASS','existing-prerequisite-semantics');
run('verify','verify-does-not-check-sops-tool',r=>r.runtime.tools.sops.sha256='bad','PASS','existing-prerequisite-semantics');
run('verify','object-output',()=>{},'PASS','aggregation');
run('verify','array-output',r=>r.commands['cosign:download'][0]=response([historical]),'PASS','aggregation');
run('verify','JSONL-output',r=>r.commands['cosign:download'][0]=response(JSON.stringify({})+'\n'+JSON.stringify(historical)),'PASS','aggregation');
run('verify','skip-invalid-before-valid',r=>r.commands['cosign:download'][0]=response([{},historical]),'PASS','aggregation');
run('verify','ignore-invalid-after-valid',r=>r.commands['cosign:download'][0]=response([historical,{}]),'PASS','aggregation');
run('verify','all-envelopes-invalid',r=>r.commands['cosign:download'][0]=response([{},{}]),'FAIL','aggregation');
run('verify','invalid-JSON-line-before-valid',r=>r.commands['cosign:download'][0]=response('{\n'+JSON.stringify(historical)),'FAIL','malformed');
run('verify','empty-line-between-JSONL',r=>r.commands['cosign:download'][0]=response('{}\n\n'+JSON.stringify(historical)),'FAIL','malformed');
run('verify','valid-first-duplicate',r=>r.commands['cosign:download'][0]=response([historical,historical]),'PASS','aggregation');

run('verify','valid-later-after-identity-mismatch',r=>{const wrong=structuredClone(historical);wrong.payload=Buffer.from('invalid').toString('base64');r.commands['cosign:download'][0]=response([wrong,historical]);},'PASS','aggregation');
run('verify','missing-signatures',r=>{const e=structuredClone(historical);delete e.signatures;r.commands['cosign:download'][0]=response(e);},'FAIL','tamper');
run('verify','empty-signatures',r=>{const e=structuredClone(historical);e.signatures=[];r.commands['cosign:download'][0]=response(e);},'FAIL','tamper');
run('verify','DSSE-payloadType-tampered',r=>{const e=structuredClone(historical);e.payloadType='changed';r.commands['cosign:download'][0]=response(e);},'FAIL','tamper');
run('verify','decoded-statement-malformed-JSON',r=>{r.files['infra/security/cosign.pub']=file(disposablePublic);r.commands['cosign:download'][0]=response(signStatement('{'));r.artifactOrigin='SYNTHETIC_DISPOSABLE_KEY';},'FAIL','malformed');
run('verify','digest-negative-control-ending-zero',r=>{const image=r.environment.PROVENANCE_CANDIDATE.slice(0,-1)+'0';synthetic(r,s=>{s.subject[0].digest.sha256=image.split('@sha256:')[1];s.predicate.candidateImage=image;});r.environment.PROVENANCE_CANDIDATE=image;},'PASS','negative-control');
run('verify','signed-predicate-build-number-string',r=>synthetic(r,s=>s.predicate.buildNumber='270'),'FAIL','identity');
run('verify','multiple-invalid-signature-then-valid-signature',r=>{const e=structuredClone(historical);e.signatures.unshift({sig:'AAAA'});r.commands['cosign:download'][0]=response(e);},'PASS','aggregation');
run('create','null-decrypted-bundle',r=>r.commands['sops:decrypt'][0]=response('null'),'FAIL','prerequisite');
run('create','private-key-object-not-writable',r=>r.commands['sops:decrypt'][0]=response({data:{privateKey:{not:'text'}}}),'FAIL','prerequisite');
run('generate','invalid-generation-time',r=>r.now='invalid','FAIL','generation');
run('invalid','unknown-action',()=>{},'FAIL','prerequisite');
for(const action of ['generate','create','verify'])test(action+' missing observation is NOT_TESTED, not a differential',()=>{const r=fixture(action);delete r.io['output-mkdir'];const p=evaluate({component:'provenance',status:'success',raw:r});assert.equal(p.decision,null);assert.equal(p.status,'NOT_TESTED');});
test('missing Provenance root is not PASS',()=>assert.equal(evaluate({component:'provenance',status:'success',raw:{}}).decision,null));
test('historical 270 signature and report are locally reverified unchanged',()=>{const before=JSON.stringify(archive),r=fixture('verify'),statement=verifyEnvelope(historical,pub);assert.equal(validate(statement,expected(r)),true);assert.deepEqual(statement.predicate,predicate);assert.equal(archive.reports['attestation-verification.json'].status,'success');assert.equal(JSON.stringify(archive),before);});
test.after(()=>fs.writeFileSync(out+'differential.json',JSON.stringify({records},null,2)));
