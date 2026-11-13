import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {validateBuildStatement} from '../provenance/build-contract.mjs';
import {evaluate} from './engine.mjs';import {replayBuildStage} from './build-provenance-replay.mjs';import {fixture,cmd,file,sha,historical,mutateSigned,disposablePublic,verifyEnvelope,pub} from './build-provenance-test-fixtures.mjs';
const out='evidence/2026-11-01/build-provenance-parent/',records=[];
function run(phase,name,change,want,branch){test(phase+' whole Build Provenance '+name,async()=>{
 const raw=fixture(phase);change(raw);const before=JSON.stringify(raw),old=await replayBuildStage(raw);assert.equal(old.oldDecision,want,old.facts.execution.diagnostic);assert.equal(old.facts.complete,true,'incomplete observations');
 const factBytes=JSON.stringify(old.facts),p=evaluate({component:'build-provenance',status:'success',raw:old.facts});assert.equal(p.decision,old.oldDecision);assert.equal(p.securityLevel,'standard');assert.equal(JSON.stringify(old.facts),factBytes);assert.deepEqual(p.rawEvidence,old.facts);assert.equal(JSON.stringify(raw),before);
 records.push({phase,name,branch,classification:'CONTROLLED_REPLAY',oldDecision:old.oldDecision,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),verifiedFactsSha256:sha(factBytes),diagnostic:old.facts.execution.diagnostic});
 fs.writeFileSync(out+'fixtures/'+phase+'--'+name+'.json',JSON.stringify({input:raw,verifiedFacts:old.facts},null,2));
});}
for(const phase of ['package','image','harbor-copy','create','verify']){
 run(phase,'valid',()=>{},'PASS','positive');
 if(phase!=='harbor-copy'){
 run(phase,'manifest-hash-mismatch',r=>r.runtime.expectedManifestSha256='bad','FAIL','prerequisite');
 run(phase,'manifest-read-error',r=>r.runtime.manifestReadError='read denied','FAIL','io');
 run(phase,'lock-read-error',r=>r.runtime.lockReadError='read denied','FAIL','io');
 run(phase,'manifest-malformed',r=>r.runtime.manifest='{','FAIL','malformed');
 }
}
test.after(()=>fs.writeFileSync(out+'differential.json',JSON.stringify({records},null,2)));

for(const phase of ['package','image','create']){
 run(phase,'lease-not-owned',r=>r.runtime.lease=cmd({spec:{holderIdentity:'foreign'}}),'FAIL','prerequisite');
 run(phase,'lease-query-failed',r=>r.runtime.lease=cmd('',1),'FAIL','infrastructure');
 run(phase,'lease-malformed',r=>r.runtime.lease=cmd('{'),'FAIL','malformed');
}
for(const phase of ['create','verify']){
 run(phase,'cosign-tool-mismatch',r=>r.runtime.tools.cosign.sha256='wrong','FAIL','prerequisite');
 run(phase,'cosign-tool-missing',r=>r.runtime.tools.cosign={error:'ENOENT'},'FAIL','infrastructure');
 for(const k of ['BUILD_PROVENANCE_IMAGE','BUILD_SOURCE_COMMIT','BUILD_SOURCE_REPOSITORY','BUILD_BUILDER_IDENTITY','BUILD_SOURCE_NUMBER'])run(phase,'missing-'+k,r=>delete r.environment[k],'FAIL','missing');
 run(phase,'tag-instead-of-candidate-digest',r=>r.environment.BUILD_PROVENANCE_IMAGE='core.harbor.domain/petclinic/petclinic:latest','FAIL','digest');
 run(phase,'source-revision-mismatch',r=>r.environment.BUILD_SOURCE_COMMIT='b'.repeat(40),'FAIL','source');
 run(phase,'builder-mismatch',r=>r.environment.BUILD_BUILDER_IDENTITY='untrusted','FAIL','builder');
 run(phase,'source-repository-mismatch',r=>r.environment.BUILD_SOURCE_REPOSITORY='other','FAIL','source');
 run(phase,'build-number-mismatch',r=>r.environment.BUILD_SOURCE_NUMBER='3','FAIL','builder');
 for(const io of ['temp-create','temp-chmod','mkdir:/tmp/build-attestation-frozen/docker','write:/tmp/build-attestation-frozen/docker/config.json','temp-remove','temp-stat','mkdir:.devsecops','write:.devsecops/build-attestation-envelope.json','write:.devsecops/build-attestation-verification.json'])run(phase,'IO-'+io.replaceAll('/','_'),r=>r.io[io]={error:'isolated IO failure'},'FAIL','io');
 run(phase,'cleanup-boolean-not-new-failure',r=>r.tempExists=true,'PASS','existing-nonblocking-cleanup');
 const offset=phase==='create'?2:0;
 for(const [name,result]of [['missing-attestation',cmd('',1)],['registry-down',cmd('',1)],['CLI-timeout',{status:null,error:'ETIMEDOUT'}],['CLI-exec-error',{status:null,error:'ENOENT'}],['malformed-output',cmd('{')],['empty-list',cmd([])],['empty-output',cmd('')],['empty-envelope',cmd({})]])run(phase,name,r=>r.commands.cosign[offset]=result,'FAIL',name.includes('attestation')?'missing':['malformed-output','empty-list','empty-output','empty-envelope'].includes(name)?'malformed':'infrastructure');
 run(phase,'public-key-file-missing',r=>r.files['infra/security/cosign.pub']={error:'ENOENT'},'FAIL','io');
 run(phase,'trusted-public-key-replaced',r=>r.files['infra/security/cosign.pub']=file(disposablePublic),'FAIL','tamper');
}
run('verify','verify-no-lease-guard',r=>r.runtime.lease=cmd('',1),'PASS','existing-prerequisite');
run('verify','verify-no-sops-guard',r=>r.runtime.tools.sops.sha256='wrong','PASS','existing-prerequisite');
run('harbor-copy','no-scanner-runtime-import',r=>r.runtime.expectedManifestSha256='wrong','PASS','existing-prerequisite');
for(const phase of ['package','image']){
 for(const io of ['mkdir:.devsecops',phase==='package'?'write:.devsecops/build-compilation.json':'write:.devsecops/build-provenance.json'])run(phase,'IO-'+io.replaceAll('/','_'),r=>r.io[io]={error:'IO failure'},'FAIL','io');
 run(phase,'git-command-failed',r=>r.commands.git[0]=cmd('',1),'FAIL','execution');
 run(phase,'invalid-source-revision',r=>r.commands.git[0]=cmd('main'),'FAIL','source');
 run(phase,'untrusted-source-repository',r=>r.commands.git[1]=cmd('http://elsewhere.invalid/untrusted.git'),'FAIL','source');
 run(phase,'dirty-source-inputs',r=>r.commands.git[2]=cmd(' M Dockerfile'),'FAIL','source');
 for(const k of ['BUILD_NUMBER','JOB_NAME','JENKINS_URL'])run(phase,'missing-'+k,r=>delete r.environment[k],'FAIL','builder');
 run(phase,'source-changed-after-build',r=>r.commands.git[3]=cmd('b'.repeat(40)),'FAIL','source');
}
run('package','Maven-failure',r=>r.commands.nice[0]=cmd('',1),'FAIL','execution');
run('package','Maven-timeout',r=>r.commands.nice[0]={status:null,error:'ETIMEDOUT'},'FAIL','infrastructure');
run('package','missing-compiled-jar',r=>r.files['target/spring-petclinic-4.0.0-SNAPSHOT.jar']={error:'ENOENT'},'FAIL','missing');
for(const [name,mutate]of [['source-mismatch',c=>c.source.commit='b'.repeat(40)],['builder-mismatch',c=>c.builder.identity='other'],['jar-checksum-mismatch',c=>c.jarSha256='0'.repeat(64)]])run('image','compilation-'+name,r=>{const c=JSON.parse(r.files['.devsecops/build-compilation.json'].value);mutate(c);r.files['.devsecops/build-compilation.json']=file(c);},'FAIL',name.includes('checksum')?'checksum':name.includes('builder')?'builder':'source');
run('image','compilation-receipt-missing',r=>r.files['.devsecops/build-compilation.json']={error:'ENOENT'},'FAIL','missing');
run('image','compilation-receipt-malformed',r=>r.files['.devsecops/build-compilation.json']=file('{'),'FAIL','malformed');
run('image','invalid-local-tag',r=>r.environment.FULL_IMAGE='registry.example/app:latest','FAIL','digest');
for(const status of [200,401,503])run('image','tag-probe-'+status,r=>{const k=Object.keys(r.network).find(k=>k.startsWith('HEAD '));r.network[k]=[{status}];},'FAIL','infrastructure');
run('image','tag-probe-network-failure',r=>{const k=Object.keys(r.network).find(k=>k.startsWith('HEAD '));r.network[k]=[{error:'DNS failure'}];},'FAIL','infrastructure');
run('image','unreviewed-dockerignore',r=>r.files['.dockerignore'].value='**\n!everything\n','FAIL','checksum');
run('image','symlink-input',r=>r.walk['target/security-packages'].push({name:'unsafe',type:'symlink'}),'FAIL','checksum');
run('image','nonregular-input',r=>r.walk['target/security-packages'].push({name:'socket',type:'socket'}),'FAIL','checksum');
run('image','package-directory-read-failed',r=>r.walk['target/security-packages']={error:'EACCES'},'FAIL','io');
const packageInput=historical.predicate.context.files.find(x=>x.name.startsWith('target/security-packages/amd64/')).name;
run('image','missing-input-checksum-file',r=>r.files[packageInput]={error:'ENOENT'},'FAIL','checksum');
run('image','input-checksum-changed-during-build',r=>r.files[packageInput]=[r.files[packageInput],{measuredSha256:'0'.repeat(64)}],'FAIL','checksum');
run('image','Buildx-command-failed',r=>r.commands.docker[0]=cmd('',1),'FAIL','execution');
run('image','Buildx-timeout',r=>r.commands.docker[0]={status:null,error:'ETIMEDOUT'},'FAIL','infrastructure');
run('image','missing-BuildKit-metadata',r=>r.files['target/platform/image-build-metadata.json']={error:'ENOENT'},'FAIL','missing');
run('image','malformed-BuildKit-metadata',r=>r.files['target/platform/image-build-metadata.json']=file('{'),'FAIL','malformed');
run('image','missing-BuildKit-digest',r=>{const m=JSON.parse(r.files['target/platform/image-build-metadata.json'].value);delete m['containerimage.digest'];r.files['target/platform/image-build-metadata.json']=file(m);},'FAIL','digest');
run('image','final-index-digest-mismatch',r=>{const k=Object.keys(r.network).find(k=>k.startsWith('GET '));r.network[k][0].bytes='replaced-index';},'FAIL','digest');
run('image','final-index-unavailable',r=>{const k=Object.keys(r.network).find(k=>k.startsWith('GET '));r.network[k][0].status=503;},'FAIL','infrastructure');
function replaceIndex(r,index){const bytes=typeof index==='string'?index:JSON.stringify(index),digest='sha256:'+sha(bytes),m=JSON.parse(r.files['target/platform/image-build-metadata.json'].value);m['containerimage.digest']=digest;r.files['target/platform/image-build-metadata.json']=file(m);r.network['GET http://10.0.0.3:30050/v2/petclinic/petclinic/manifests/'+digest]=[{status:200,bytes}];}
for(const arch of ['amd64','arm64']){
 run('image','missing-index-platform-'+arch,r=>{const x=r.syntheticIndex.index;x.manifests=x.manifests.filter(x=>x.platform.architecture!==arch);replaceIndex(r,x);},'FAIL','architecture');
 run('image','duplicate-index-platform-'+arch,r=>{const x=r.syntheticIndex.index;x.manifests.push(x.manifests.find(x=>x.platform.architecture===arch));replaceIndex(r,x);},'FAIL','architecture');
}
run('image','index-wrong-OS',r=>{r.syntheticIndex.index.manifests[0].platform.os='windows';replaceIndex(r,r.syntheticIndex.index);},'FAIL','architecture');
run('image','malformed-index-with-correct-byte-digest',r=>replaceIndex(r,'{'),'FAIL','malformed');
run('image','missing-native-platform-metadata-not-added-gate',r=>{const m=JSON.parse(r.files['target/platform/image-build-metadata.json'].value);delete m['buildx.build.provenance/linux/amd64'];r.files['target/platform/image-build-metadata.json']=file(m);},'PASS','existing-not-enforced');
for(const phase of ['create','verify']){
 for(const [name,mutate,branch]of [
 ['wrong-source',p=>p.source.commit='b'.repeat(40),'source'],['wrong-builder',p=>p.builder.identity='other','builder'],['wrong-subject-candidate',p=>p.candidateImage=p.candidateImage.slice(0,-1)+'0','digest'],['missing-checksum',p=>delete p.context.files[0].sha256,'checksum'],['malformed-checksum',p=>p.context.files[0].sha256='wrong','checksum'],['empty-checksum-set',p=>p.context.files=[],'checksum'],['missing-context',p=>delete p.context,'missing'],['wrong-compilation-source',p=>p.compilation.sourceCommit='b'.repeat(40),'source'],['missing-jar-checksum',p=>delete p.compilation.jarSha256,'checksum'],['missing-BuildKit-hash',p=>delete p.buildkit.metadataSha256,'checksum'],['missing-platform',p=>p.platforms=['linux/amd64'],'architecture'],['wrong-platform-order',p=>p.platforms.reverse(),'architecture'],['duplicate-platform',p=>p.platforms.push('linux/arm64'),'architecture'],['wrong-chronology',p=>p.finishedAt='2000-01-01','metadata'],['wrong-build-type',p=>p.buildType='other','metadata'],
 ])run(phase,name,r=>mutateSigned(r,mutate),'FAIL',branch);
 run(phase,'80-valid-context-entries-not-new-count-gate',r=>mutateSigned(r,p=>p.context.files.pop()),'PASS','existing-not-enforced');
 run(phase,'wellformed-checksum-is-not-rehashed-by-consumer',r=>mutateSigned(r,p=>p.context.files[0].sha256='0'.repeat(64)),'PASS','existing-not-enforced');
 run(phase,'BuildKit-outputDigest-not-extra-consumer-rule',r=>mutateSigned(r,p=>p.buildkit.outputDigest='sha256:'+'0'.repeat(64)),'PASS','existing-not-enforced');
 const offset=phase==='create'?2:0;
 run(phase,'tampered-payload',r=>{const e=structuredClone(historical.envelope);e.payload=Buffer.from('tampered').toString('base64');r.commands.cosign[offset]=cmd(e);},'FAIL','tamper');
 run(phase,'signature-replaced',r=>{const e=structuredClone(historical.envelope);e.signatures=[{sig:'AAAA'}];r.commands.cosign[offset]=cmd(e);},'FAIL','tamper');
 run(phase,'array-envelope-output',r=>r.commands.cosign[offset]=cmd([historical.envelope]),'PASS','aggregation');
 run(phase,'JSONL-skip-invalid-then-valid',r=>r.commands.cosign[offset]=cmd('{}\n'+JSON.stringify(historical.envelope)),'PASS','aggregation');
 run(phase,'all-envelopes-invalid',r=>r.commands.cosign[offset]=cmd([{},{}]),'FAIL','aggregation');
 run(phase,'array-valid-first-ignores-later',r=>r.commands.cosign[offset]=cmd([historical.envelope,{}]),'PASS','aggregation');
}
run('create','sops-tool-mismatch',r=>r.runtime.tools.sops.sha256='wrong','FAIL','prerequisite');
run('create','decrypt-command-failed',r=>r.commands.sops[0]=cmd('',1),'FAIL','execution');
run('create','decrypt-malformed',r=>r.commands.sops[0]=cmd('{'),'FAIL','malformed');
run('create','decrypted-key-missing',r=>r.commands.sops[0]=cmd({data:{}}),'FAIL','missing');
run('create','public-key-output-mismatch',r=>r.commands.cosign[0]=cmd('other'),'FAIL','tamper');
run('create','attest-command-failed',r=>r.commands.cosign[1]=cmd('',1),'FAIL','execution');
run('create','predicate-file-missing',r=>r.files['.devsecops/build-provenance.json']={error:'ENOENT'},'FAIL','missing');
run('create','predicate-file-malformed',r=>r.files['.devsecops/build-provenance.json']=file('{'),'FAIL','malformed');

for(const k of ['HARBOR_USER','HARBOR_PASS'])run('harbor-copy','missing-'+k,r=>delete r.environment[k],'FAIL','prerequisite');
run('harbor-copy','invalid-tag',r=>r.environment.IMAGE_TAG='latest','FAIL','digest');
const harborNetworkKeys=Object.keys(fixture('harbor-copy').network).filter(k=>!k.startsWith('HEAD http://10.')&&!k.endsWith(fixture('harbor-copy').syntheticIndex.digest));
for(const [i,key]of harborNetworkKeys.entries()){
 run('harbor-copy','registry-HTTP-failure-'+i,r=>r.network[key]=[{status:401}],'FAIL','infrastructure');
 run('harbor-copy','registry-transient-exhaustion-'+i,r=>r.network[key]=Array.from({length:3},()=>({status:503})),'FAIL','infrastructure');
 run('harbor-copy','registry-network-retry-exhaustion-'+i,r=>r.network[key]=Array.from({length:3},()=>({error:'DNS/reset failure'})),'FAIL','infrastructure');
}
run('harbor-copy','source-final-digest-header-mismatch',r=>{const k=Object.keys(r.network).find(k=>k.startsWith('PUT ')&&k.endsWith('/manifests/0.10.0-ci-1000002'));r.network[k][0].headers['docker-content-digest']='sha256:'+'f'.repeat(64);},'FAIL','digest');
run('harbor-copy','child-digest-header-mismatch',r=>{const k=Object.keys(r.network).find(k=>k.startsWith('PUT ')&&k.includes('/manifests/sha256:'));r.network[k][0].headers['docker-content-digest']='sha256:'+'f'.repeat(64);},'FAIL','digest');
run('harbor-copy','missing-final-architecture',r=>{const key=Object.keys(r.network).find(k=>k.startsWith('GET ')&&k.endsWith('/manifests/0.10.0-ci-1000002')),x=JSON.parse(r.network[key][0].bytes);x.manifests.pop();r.network[key][0].bytes=JSON.stringify(x);},'FAIL','architecture');
run('harbor-copy','copy-report-write-failed',r=>r.io['write:target/platform/harbor-copy.json']={error:'EACCES'},'FAIL','io');
run('harbor-copy','transient-registry-recovers',r=>{const key=Object.keys(r.network).find(k=>k.includes('/service/token?'));r.network[key].unshift({status:503});},'PASS','infrastructure-recovery');
function uploadScenario(r){
 const x=r.syntheticIndex.children[0],src='http://10.0.0.3:30050/v2/petclinic/petclinic',dst='http://harbor-core.harbor.svc.cluster.local/v2/petclinic/petclinic';
 r.network['HEAD '+dst+'/blobs/'+x.json.config.digest]=[{status:404}];r.network['GET '+src+'/blobs/'+x.json.config.digest]=[{status:200,bytes:x.blob,headers:{'content-length':String(Buffer.byteLength(x.blob))}}];
 r.network['POST '+dst+'/blobs/uploads/']=[{status:202,headers:{location:'/v2/petclinic/petclinic/blobs/uploads/frozen'}}];r.network['PUT '+dst+'/blobs/uploads/frozen?digest='+encodeURIComponent(x.json.config.digest)]=[{status:201}];
}
run('harbor-copy','blob-copy-full-positive',uploadScenario,'PASS','blob-transfer');
for(const [name,keyType,status]of [['source-blob-unavailable','GET',404],['upload-initialization-rejected','POST',400],['blob-upload-rejected','PUT',400]])run('harbor-copy',name,r=>{uploadScenario(r);const key=Object.keys(r.network).find(k=>k.startsWith(keyType+' ')&&k.includes(keyType==='GET'?'/blobs/sha256:':keyType==='POST'?'/blobs/uploads/':'/blobs/uploads/frozen?'));r.network[key]=[{status}];},'FAIL','blob-transfer');
run('harbor-copy','blob-lookup-not404',r=>{const key=Object.keys(r.network).find(k=>k.startsWith('HEAD http://harbor-'));r.network[key]=[{status:401}];},'FAIL','blob-transfer');

for(const phase of ['package','image','create','verify'])test(phase+' incomplete observations cannot PASS',async()=>{const r=fixture(phase);delete r.io[phase==='package'||phase==='image'?'mkdir:.devsecops':'temp-create'];const old=await replayBuildStage(r),result=evaluate({component:'build-provenance',status:'success',raw:old.facts});assert.equal(result.status,'NOT_TESTED');assert.equal(result.decision,null);});
test('missing verified Build facts cannot PASS',()=>assert.equal(evaluate({component:'build-provenance',status:'success',raw:{}}).decision,null));
test('successful exit without report cannot PASS',async()=>{const {facts}=await replayBuildStage(fixture('verify'));facts.artifacts={};const r=evaluate({component:'build-provenance',status:'success',raw:facts});assert.equal(r.status,'NOT_TESTED');assert.equal(r.decision,null);});
test('Policy reads verifier facts without touching source inputs or BuildKit metadata',async()=>{
 const {facts}=await replayBuildStage(fixture('image')),read=fs.readFileSync,paths=[];
 try{fs.readFileSync=function(p,...args){paths.push(String(p));return read.call(this,p,...args);};assert.equal(evaluate({component:'build-provenance',status:'success',raw:facts}).decision,'PASS');}finally{fs.readFileSync=read;}
 assert.ok(!paths.some(p=>p.endsWith('/Dockerfile')||p.endsWith('/.dockerignore')||p.includes('/target/')||p.endsWith('.jar')));
});

for(const input of historical.predicate.context.files)run('image','checksum-continuity-'+input.name.replaceAll('/','_'),r=>{
 const original=r.files[input.name],changed={...original,measuredSha256:'0'.repeat(64)};
 r.files[input.name]=input.name==='.dockerignore'?[original,original,original,changed]:input.name.endsWith('.jar')?[original,original,changed]:[original,changed];
},'FAIL','81-input-checksum-continuity');
run('invalid','explicit-unknown-phase',()=>{},'FAIL','unsupported');
run('harbor-copy','tag-changed-no-added-cross-receipt-rule',r=>{
 const bytes=JSON.stringify({...r.syntheticIndex.index,annotations:{'fixture.tag':'replaced-index'}}),digest='sha256:'+sha(bytes),key=Object.keys(r.network).find(k=>k.startsWith('GET ')&&k.endsWith('/manifests/0.10.0-ci-1000002')),target=Object.keys(r.network).find(k=>k.startsWith('PUT ')&&k.endsWith('/manifests/0.10.0-ci-1000002'));
 r.network[key][0]={status:200,bytes,headers:{'docker-content-digest':digest}};r.network[target][0].headers['docker-content-digest']=digest;
},'PASS','existing-not-enforced');
test('historical producer 2 to consumer 270 evidence remains bound and unchanged',()=>{
 const before=JSON.stringify(historical),p=historical.predicate,metadata=JSON.parse(historical.metadata);assert.equal(p.context.files.length,81);assert.deepEqual(p.compilation,historical.compilation);assert.equal(sha(Buffer.from(historical.metadata)),p.buildkit.metadataSha256);assert.equal(metadata['containerimage.digest'],p.candidateImage.split('@')[1]);assert.equal(p.buildkit.outputDigest,metadata['containerimage.digest']);
 for(const arch of ['amd64','arm64'])assert.ok(metadata['buildx.build.provenance/linux/'+arch]);
 const s=verifyEnvelope(historical.envelope,pub);assert.deepEqual(s.predicate,p);assert.ok(validateBuildStatement(s,historical.report.expected));
 const audit=JSON.parse(fs.readFileSync('evidence/2026-11-01/remaining-policy/archived-270.json')).reports;assert.deepEqual(verifyEnvelope(audit['build-attestation-envelope.json'],pub).predicate,p);assert.equal(JSON.stringify(historical),before);
});
