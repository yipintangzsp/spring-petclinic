import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import path from 'node:path';import crypto from 'node:crypto';
import {checkCosignVerification} from '../cosign-verification.mjs';import {cosignObservations,MissingCosignEvidence} from './cosign-observations.mjs';import {evaluate} from './engine.mjs';
const out='evidence/2026-11-01/cosign-parent/',records=[],read=p=>JSON.parse(fs.readFileSync(p)),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const signing=fs.readFileSync('infra/security/signing.mjs','utf8').replace(/^import .*;\s*$/gm,''),generic=fs.readFileSync('infra/security/manager/tool.mjs','utf8').replace(/^import .*;\s*$/gm,''),runtime=fs.readFileSync('infra/security/scanner-runtime.mjs','utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
const response=(stdout='',status=0,stderr='')=>({stdout:typeof stdout==='string'?stdout:JSON.stringify(stdout),status,stderr}),file=value=>({value:typeof value==='string'?value:JSON.stringify(value)}),pub=fs.readFileSync('infra/security/cosign.pub','utf8'),hash=n=>'sha256:'+String(n).repeat(64),image=n=>'core.harbor.domain/petclinic/petclinic@'+hash(n),claim=d=>[{critical:{image:{'docker-manifest-digest':d}}}];
function fixture(stage){
 const manifest=fs.readFileSync('infra/security/scanner-tools.json','utf8'),tools=JSON.parse(manifest);
 const r={classification:'SYNTHETIC_FROZEN_COMPLETE_STAGE',stage,configuration:{build:270,project:'disposable-policy-fixture',mode:'enforce',sourceRoot:'/fixture/project',image:image('a'),cosignPublicKey:'trust.pub'},environment:{BUILD_NUMBER:'270',SIGNING_AGE_FILE:'/fixture/NOT_A_REAL_KEY',HARBOR_USER:'synthetic-user',HARBOR_PASS:'synthetic-password'},runtime:{manifest,expectedManifestSha256:sha(manifest),lease:response({spec:{holderIdentity:'jenkins-petclinic-270'}}),tools:Object.fromEntries(tools.files.filter(x=>['cosign','sops'].includes(x.path)).map(x=>[x.path,{sha256:x.sha256}]))},files:{'.git-sha':file('fixture-source'),'infra/security/cosign.pub':file(pub),'target/platform/image.json':file({source:'fixture-source',digest:hash('a')}),'target/platform/harbor.json':file({digest:hash('a'),scan_status:'Success',scans:[{digest:hash('b')},{digest:hash('c')}]}),'.devsecops/release-evidence.json':file({source:'fixture-source',imageDigest:hash('a')}),'proof-after-write':file('synthetic artifact after signing')},io:Object.fromEntries(['output-mkdir','temp-create','temp-chmod','key-write','docker-mkdir','docker-write','proof-write','temp-remove','temp-exists','signing-report-write','manager-report-write'].map(k=>[k,{value:k==='temp-exists'?false:undefined}])),commands:{'sops:decrypt':[response({schema:1,data:{privateKey:'SYNTHETIC_NOT_PRIVATE_KEY_MATERIAL',password:'SYNTHETIC_PASSWORD'}})],'cosign:public-key':[response(pub)],'cosign:sign':[response(),response(),response()],'cosign:generate-key-pair':[response()],'cosign:sign-blob':[response()],'cosign:verify-blob':[response()]},registry:[],admissions:[],currentImage:response({spec:{template:{spec:{containers:[{image:image('a')}]}}}})};
 if(stage==='admission'){
  r.registry.push({ok:true,status:200,body:{token:'synthetic-token'}});const refs=[];
  for(const kind of ['signed','unsigned','wrong-key']){
   const config=Buffer.from(JSON.stringify({architecture:'arm64',os:'linux',config:{Labels:{'platform.test':kind,'platform.build':'270'}},rootfs:{type:'layers',diff_ids:[]}})),d='sha256:'+sha(config);
   const manifest=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{mediaType:'application/vnd.oci.image.config.v1+json',digest:d,size:config.length},layers:[]}));refs.push('sha256:'+sha(manifest));
   r.registry.push({ok:true,status:202,headers:{location:'/v2/petclinic/signature-fixtures/blobs/uploads/frozen'}},{ok:true,status:201},{ok:true,status:201,headers:{'docker-content-digest':refs.at(-1)}});
  }
  r.commands['cosign:verify']=[response(claim(refs[0])),response(claim(refs[0])),response('',1,'no signatures found'),response('',1,'no matching signatures: invalid signature')];
  r.admissions=[response('{}'),response('',1,'devsecops-signed-images: no signatures found'),response('',1,'devsecops-signed-images: no matching signatures')];
 }else if(stage==='bootstrap')r.commands['cosign:verify']=[response(claim(hash('a'))),response(claim('sha256:a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268'))];
 else r.commands['cosign:verify']=['a','b','c'].map(n=>response(claim(hash(n))));
 return r;
}
async function oracle(raw){
 const f=cosignObservations(raw),writes={},trace=f.trace,c=raw.configuration,root=read('infra/security/scanner-tools.json').root;let proofWritten=false;
 const process={argv:['node','frozen',raw.stage==='generic'?'cosign':raw.stage],env:{...raw.environment}};
 const fsFake={readFileSync:p=>{
  if(p==='infra/security/scanner-tools.json'){if(raw.runtime.manifestReadError)throw Error(raw.runtime.manifestReadError);return raw.runtime.manifest;}
  if(p==='infra/security/tools-lock.json'){if(raw.runtime.lockReadError)throw Error(raw.runtime.lockReadError);return JSON.stringify({supplyChain:{scanner_manifest_sha256:raw.runtime.expectedManifestSha256}});}
  if(p.startsWith(root+'/')){const t=f.need(raw.runtime.tools,p.slice(root.length+1));if(t.error)throw Error(t.error);return {observedHash:t.sha256};}
  if(p==='.devsecops/manager-config.json')return JSON.stringify(c);
  if(p==='.devsecops/release-evidence.json'&&proofWritten)return f.file('proof-after-write');
  return f.file(p);
 },readlinkSync:p=>f.need(raw.runtime.tools,p.slice(root.length+1)).symlink,
 mkdirSync:p=>f.io(p==='.devsecops'?'output-mkdir':'docker-mkdir'),mkdtempSync:()=>{f.io('temp-create');return '/tmp/cosign-frozen';},chmodSync:()=>f.io('temp-chmod'),
 writeFileSync:(p,v)=>{const k=p.endsWith('/cosign.key')?'key-write':p.endsWith('/docker/config.json')?'docker-write':p==='.devsecops/release-evidence.json'?'proof-write':p.endsWith('-manager.json')?'manager-report-write':'signing-report-write';f.io(k);if(k==='proof-write')proofWritten=true;if(k.endsWith('report-write'))writes[p]=JSON.parse(v);},rmSync:()=>f.io('temp-remove'),existsSync:()=>f.io('temp-exists')};
 const spawnSync=(bin,args)=>{if(bin==='kubectl')return raw.runtime.lease;return f.command(path.basename(bin),args);};
 const cryptoFake={createHash:algorithm=>({update:value=>({digest:encoding=>value?.observedHash??crypto.createHash(algorithm).update(value).digest(encoding)})})};
 const context={fs:fsFake,path,os:{tmpdir:()=>'/tmp'},crypto:cryptoFake,spawnSync,process,Buffer,URL,AbortSignal,checkCosignVerification,console:{log:()=>{}}};
 try{
 const run=vm.runInNewContext('(function(){'+runtime+';return {requireLease,verifyTools,toolchain};})()',context);Object.assign(context,run);
 context.read=()=>{const r=raw.currentImage;if(r.error||r.status!==0)throw Error('Current image query failed');return JSON.parse(r.stdout);};
 context.kube=(args,input,allowed)=>{const r=f.admission(args,input);if(r.error||!allowed.includes(r.status))throw Error('Kube execution failed');return r;};
 context.fetch=async(url,options)=>{const r=f.registry(url,options);return {ok:r.ok,status:r.status,headers:{get:key=>r.headers?.[key]??null},json:async()=>{if(r.jsonError)throw Error('JSON failure');return r.body;}};};
 await vm.runInNewContext('(async()=>{'+(raw.stage==='generic'?generic:signing)+'})()',context);return {decision:process.exitCode===10&&c.mode==='audit'?'WARN':process.exitCode?'FAIL':'PASS',writes,trace};}catch(e){return {decision:e instanceof MissingCosignEvidence?null:'FAIL',reason:e.message,writes,trace};}
}
function run(stage,name,change,expected,branch){test(stage+' complete Cosign '+name,async()=>{
 const raw=fixture(stage);change(raw);const before=JSON.stringify(raw),old=await oracle(raw),p=evaluate({component:'cosign',status:'success',raw});
 assert.equal(old.decision,expected,'legacy: '+old.reason);assert.equal(p.decision,old.decision,'policy: '+p.reason);assert.equal(p.securityLevel,'standard');assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);
 assert.deepEqual(p.trace,JSON.parse(JSON.stringify(old.trace)),'external command arguments/digest bindings differ');
 if(p.decision==='PASS'){const report=Object.values(old.writes)[0];assert.ok(report);assert.deepEqual(p.report.images,report.images);assert.deepEqual(p.report.cases,report.cases);assert.deepEqual(p.report.verification,report.verification);assert.equal(p.report.temporaryPrivateFilesRemoved,report.temporaryPrivateFilesRemoved);}
 records.push({stage,name,branch,classification:raw.classification,oldDecision:old.decision,standardDecision:p.decision,rawPreserved:true,legacyReason:old.reason,policyReason:p.reason,failurePhase:p.failurePhase,externalTraceIdentical:true,inputSha256:sha(before)});
 fs.writeFileSync(out+'fixtures/'+stage+'--'+name+'.json',JSON.stringify(raw,null,2));
});}
for(const stage of ['admission','bootstrap','release','generic']){
 run(stage,'valid',()=>{},'PASS','positive');
 run(stage,'lease-not-owned',r=>r.runtime.lease=response({spec:{holderIdentity:'foreign'}}),'FAIL','prerequisite');
 run(stage,'lease-query-failure',r=>r.runtime.lease=response('',1,'timeout'),'FAIL','infrastructure');
 run(stage,'lease-malformed',r=>r.runtime.lease=response('{'),'FAIL','prerequisite');
 run(stage,'manifest-hash-mismatch',r=>r.runtime.expectedManifestSha256='wrong','FAIL','prerequisite');
 run(stage,'cosign-tool-hash-mismatch',r=>r.runtime.tools.cosign.sha256='wrong','FAIL','prerequisite');
 run(stage,'tool-file-read-failure',r=>r.runtime.tools.cosign={error:'absent'},'FAIL','infrastructure');
 for(const [name,result]of [ ['missing-signature',response('',1,'no signatures found')],['wrong-key',response('',1,'invalid signature')],['different-digest',response('',1,'no matching signatures: digest mismatch')],['malformed-signature',response('',1,'signature verification failed: malformed signature')],['registry-down',response('',1,'connection refused')],['timeout',response('',null,'timeout')],['spawn-error',{status:null,error:'ENOENT',stderr:'',stdout:''}],['invalid-JSON',response('{')],['empty-signatures',response([])] ])run(stage,name,r=>r.commands['cosign:verify'][0]=result,'FAIL',name.includes('digest')?'digest-binding':['registry-down','timeout','spawn-error'].includes(name)?'infrastructure':'signature');
 run(stage,'source-read-failure',r=>r.files['.git-sha']={error:'read denied'},'FAIL','infrastructure');
 if(stage!=='generic'){
  run(stage,'wrong-claim-digest',r=>r.commands['cosign:verify'][0]=response(claim(hash('f'))),'FAIL','digest-binding');
  run(stage,'claim-missing-digest',r=>r.commands['cosign:verify'][0]=response([{}]),'FAIL','digest-binding');
  run(stage,'one-of-many-claims-wrong',r=>r.commands['cosign:verify'][0]=response([...JSON.parse(r.commands['cosign:verify'][0].stdout),...claim(hash('f'))]),'FAIL','digest-binding');
  run(stage,'public-key-mismatch',r=>r.commands['cosign:public-key'][0]=response('wrong-public-key'),'FAIL','identity');
  run(stage,'public-key-command-failure',r=>r.commands['cosign:public-key'][0]=response('',1),'FAIL','infrastructure');
  run(stage,'sops-tool-mismatch',r=>r.runtime.tools.sops.sha256='wrong','FAIL','prerequisite');
  run(stage,'decryption-failed',r=>r.commands['sops:decrypt'][0]=response('',1),'FAIL','prerequisite');
  run(stage,'invalid-bundle-JSON',r=>r.commands['sops:decrypt'][0]=response('{'),'FAIL','prerequisite');
  run(stage,'invalid-bundle-schema',r=>r.commands['sops:decrypt'][0]=response({schema:2,data:{privateKey:'synthetic',password:'synthetic'}}),'FAIL','prerequisite');
  run(stage,'bundle-key-missing',r=>r.commands['sops:decrypt'][0]=response({schema:1,data:{password:'synthetic'}}),'FAIL','prerequisite');
  run(stage,'bundle-password-missing',r=>r.commands['sops:decrypt'][0]=response({schema:1,data:{privateKey:'synthetic'}}),'FAIL','prerequisite');
  run(stage,'sign-command-failure',r=>r.commands['cosign:sign'][0]=response('',1),'FAIL','infrastructure');
  for(const k of ['SIGNING_AGE_FILE','HARBOR_USER','HARBOR_PASS'])run(stage,'missing-'+k,r=>delete r.environment[k],'FAIL','prerequisite');
  for(const k of ['output-mkdir','temp-create','temp-chmod','key-write','docker-mkdir','docker-write','temp-remove','signing-report-write'])run(stage,'IO-failure-'+k,r=>r.io[k]={error:'isolated write denied'},'FAIL','io-cleanup');
  run(stage,'cleanup-existence-false-observation',r=>r.io['temp-exists']={value:true},'PASS','existing-nonblocking-cleanup-field');
 }
}
for(const [index,kind]of [[1,'signed'],[2,'unsigned'],[3,'wrong-key']]){
 run('admission',kind+'-unexpected-CLI-result',r=>r.commands['cosign:verify'][index]=kind==='signed'?response('',1,'invalid signature'):response([]),'FAIL','signature-classification');
 run('admission',kind+'-registry-error',r=>r.commands['cosign:verify'][index]=response('',1,'registry TLS handshake timeout'),'FAIL','infrastructure');
 run('admission',kind+'-spawn-error',r=>r.commands['cosign:verify'][index]={status:null,error:'timeout',stderr:'no signatures found'},'FAIL','infrastructure');
 run('admission',kind+'-admission-inverted',r=>r.admissions[index-1]=kind==='signed'?response('',1,'devsecops-signed-images denied'):response('{}'),'FAIL','admission');
 run('admission',kind+'-admission-query-failed',r=>r.admissions[index-1]=response('',2,'connection refused'),'FAIL','infrastructure');
}
run('admission','wrong-admission-policy',r=>r.admissions[1]=response('',1,'unrelated-policy denied'),'FAIL','admission');
run('admission','malformed-signature-recognized-rejection',r=>r.commands['cosign:verify'][2]=response('',1,'invalid signature: malformed encoding'),'PASS','expected-signature-rejection');
run('admission','negative-cli-non-signature-error',r=>r.commands['cosign:verify'][3]=response('',1,'permission denied'),'FAIL','infrastructure');
for(let i=0;i<10;i++){
 run('admission','registry-HTTP-failure-'+i,r=>r.registry[i]={ok:false,status:503},'FAIL','registry');
 run('admission','registry-network-failure-'+i,r=>r.registry[i]={error:'connection reset'},'FAIL','infrastructure');
}
for(const i of [3,6,9])run('admission','registry-replaced-digest-'+i,r=>r.registry[i].headers['docker-content-digest']=hash('f'),'FAIL','digest-binding');
run('admission','malformed-token-JSON',r=>r.registry[0].jsonError=true,'FAIL','registry');
run('admission','invalid-upload-location',r=>r.registry[1].headers.location='http://[invalid','FAIL','registry');
run('bootstrap','wrong-registry-ref',r=>r.currentImage=response({spec:{template:{spec:{containers:[{image:'outside.example/petclinic@'+hash('a')}]}}}}),'FAIL','reference');
run('bootstrap','tag-instead-of-digest',r=>r.currentImage=response({spec:{template:{spec:{containers:[{image:'core.harbor.domain/petclinic/petclinic:latest'}]}}}}),'FAIL','reference');
run('bootstrap','current-query-failed',r=>r.currentImage=response('',1),'FAIL','infrastructure');
run('bootstrap','current-query-malformed',r=>r.currentImage=response('{'),'FAIL','infrastructure');
for(const [name,change]of [ ['source-mismatch',r=>r.source='other'],['built-digest-replaced',r=>r.digest=hash('f')] ])run('release',name,r=>{const b=JSON.parse(r.files['target/platform/image.json'].value);change(b);r.files['target/platform/image.json']=file(b);},'FAIL','release-binding');
for(const [name,change]of [['scan-not-completed',h=>h.scan_status='Running'],['single-arch-scan',h=>h.scans.pop()],['scan-parent-mismatch',h=>h.digest=hash('f')],['invalid-child-digest',h=>h.scans[0].digest='wrong']])run('release',name,r=>{const h=JSON.parse(r.files['target/platform/harbor.json'].value);change(h);r.files['target/platform/harbor.json']=file(h);},'FAIL','release-binding');
for(const field of ['source','imageDigest'])run('release','artifact-'+field+'-mismatch',r=>{const p=JSON.parse(r.files['.devsecops/release-evidence.json'].value);p[field]='wrong';r.files['.devsecops/release-evidence.json']=file(p);},'FAIL','artifact-binding');
for(const verb of ['sign-blob','verify-blob'])run('release',verb+'-failed',r=>r.commands['cosign:'+verb][0]=response('',1,'invalid signature'),'FAIL','artifact-signature');
run('release','artifact-write-failure',r=>r.io['proof-write']={error:'write denied'},'FAIL','io-cleanup');
run('release','artifact-reread-failure',r=>r.files['proof-after-write']={error:'read denied'},'FAIL','io-cleanup');
for(const [name,change]of [['tag',c=>c.image='registry/app:latest'],['missing-key',c=>delete c.cosignPublicKey],['trust-path-outside',c=>c.cosignPublicKey='../outside.pub'],['empty-image',c=>delete c.image]])run('generic',name,r=>change(r.configuration),'FAIL','reference');
run('generic','report-write-failure',r=>r.io['manager-report-write']={error:'write denied'},'FAIL','io-cleanup');
run('generic','audit-execution-error-not-WARN',r=>{r.configuration.mode='audit';r.commands['cosign:verify'][0]=response('',1,'no signatures found');},'FAIL','audit-semantics');
run('generic','audit-valid',r=>r.configuration.mode='audit','PASS','audit-semantics');

for(const stage of ['admission','bootstrap','release','generic']){
 run(stage,'runtime-manifest-read-failed',r=>r.runtime.manifestReadError='read denied','FAIL','prerequisite');
 run(stage,'runtime-lock-read-failed',r=>r.runtime.lockReadError='read denied','FAIL','prerequisite');
 run(stage,'runtime-malformed-manifest',r=>r.runtime.manifest='{','FAIL','prerequisite');
 run(stage,'explicit-holder-accepted',r=>{r.environment.HEAVY_HOLDER='isolated-holder';r.runtime.lease=response({spec:{holderIdentity:'isolated-holder'}});},'PASS','prerequisite');
 if(stage!=='generic'){
  run(stage,'trusted-public-file-unreadable',r=>r.files['infra/security/cosign.pub']={error:'read denied'},'FAIL','identity');
  run(stage,'cleanup-existence-query-error',r=>r.io['temp-exists']={error:'stat denied'},'FAIL','io-cleanup');
  run(stage,'sign-spawn-error',r=>r.commands['cosign:sign'][0]={error:'ENOENT',status:null},'FAIL','infrastructure');
 }
}
for(const index of [1,2])run('release','later-image-verification-failed-'+index,r=>r.commands['cosign:verify'][index]=response('',1,'invalid signature'),'FAIL','aggregation');
run('admission','wrong-key-sign-command-failed',r=>r.commands['cosign:sign'][1]=response('',1),'FAIL','infrastructure');
run('admission','key-generation-command-failed',r=>r.commands['cosign:generate-key-pair'][0]=response('',1),'FAIL','infrastructure');
run('admission','signed-post-sign-output-malformed-array',r=>r.commands['cosign:verify'][0]=response({invalid:'shape'}),'FAIL','signature');
run('admission','signed-post-sign-null-output',r=>r.commands['cosign:verify'][0]=response('null'),'FAIL','signature');
run('admission','token-body-null',r=>r.registry[0].body=null,'FAIL','registry');
run('admission','missing-token-current-no-validation',r=>r.registry[0].body={},'PASS','existing-token-semantics');
run('admission','missing-upload-location-current-relative-URL',r=>r.registry[1].headers={},'PASS','existing-token-semantics');
run('admission','missing-manifest-digest-header',r=>r.registry[3].headers={},'FAIL','digest-binding');
run('bootstrap','rollback-baseline-only-deduplicated',r=>{r.currentImage=response({spec:{template:{spec:{containers:[{image:image('a').replace(hash('a'),'sha256:a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268')}]}}}});r.commands['cosign:verify'][0]=response(claim('sha256:a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268'));},'PASS','aggregation');
for(const p of ['target/platform/image.json','target/platform/harbor.json','.devsecops/release-evidence.json']){
 run('release','unreadable-'+path.basename(p),r=>r.files[p]={error:'read denied'},'FAIL','io-cleanup');
 run('release','malformed-'+path.basename(p),r=>r.files[p]=file('{'),'FAIL','release-binding');
}
run('generic','null-verification-output',r=>r.commands['cosign:verify'][0]=response('null'),'FAIL','signature');
run('generic','nonarray-object-output',r=>r.commands['cosign:verify'][0]=response({}),'FAIL','signature');
run('admission','invalid-verifier-exit-range',r=>r.commands['cosign:verify'][2]=response('',256,'invalid signature'),'FAIL','infrastructure');
run('admission','different-digest-negative-rejection',r=>r.commands['cosign:verify'][3]=response('',1,'no matching signatures: digest mismatch'),'PASS','expected-signature-rejection');

run('admission','signed-CLI-unrecognized-error',r=>r.commands['cosign:verify'][1]=response('',1,'unknown verification error'),'FAIL','infrastructure');
run('admission','unsigned-malformed-signature-unrecognized',r=>r.commands['cosign:verify'][2]=response('',1,'invalid JSON metadata'),'FAIL','infrastructure');
run('admission','wrong-key-malformed-signature-unrecognized',r=>r.commands['cosign:verify'][3]=response('',1,'invalid JSON metadata'),'FAIL','infrastructure');
run('release','tampered-artifact-rejected-by-Cosign',r=>r.commands['cosign:verify-blob'][0]=response('',1,'signature verification failed: tampered artifact'),'FAIL','tamper');
run('bootstrap','second-baseline-wrong-claim-digest',r=>r.commands['cosign:verify'][1]=response(claim(hash('f'))),'FAIL','aggregation');
run('release','child-valid-signature-wrong-digest',r=>r.commands['cosign:verify'][2]=response(claim(hash('f'))),'FAIL','digest-binding');
run('release','all-scanned-digests-deduplicated',r=>{const h=JSON.parse(r.files['target/platform/harbor.json'].value);h.scans=[{digest:hash('a')},{digest:hash('a')}];r.files['target/platform/harbor.json']=file(h);},'PASS','aggregation');
run('invalid','unknown-explicit-mode',()=>{},'FAIL','prerequisite');
test('missing command exit status never becomes a Policy decision',()=>{const r=fixture('admission');delete r.commands['cosign:verify'][0].status;assert.equal(evaluate({component:'cosign',status:'success',raw:r}).status,'NOT_TESTED');});
test('low / override / audit cannot soften a frozen Cosign failure',()=>{const r=fixture('generic');r.commands['cosign:verify'][0]=response('',1,'no signatures found');for(const config of [{securityLevel:'low'},{securityLevel:'strict'},{mode:'audit',componentOverrides:{cosign:{Critical:'PASS'}}}])assert.equal(evaluate({component:'cosign',status:'success',raw:r},config).decision,'FAIL');});
// A receipt is historical evidence, not a fabricated complete execution transcript.
test('archived Jenkins 270 Cosign receipt is preserved and digest references match generated fixture bytes',async()=>{
 const archive=read('evidence/2026-11-01/remaining-policy/archived-270.json'),receipt=archive.reports['signing-admission.json'],before=JSON.stringify(receipt);
 assert.equal(archive.build,270);assert.equal(receipt.status,'success');const r=fixture('admission'),old=await oracle(r),report=Object.values(old.writes)[0];
 assert.deepEqual(report.images,receipt.images);assert.deepEqual(report.cases.map(({case:kind,image,allowed,cliVerified})=>({case:kind,image,allowed,cliVerified})),receipt.cases.map(({case:kind,image,allowed,cliVerified})=>({case:kind,image,allowed,cliVerified})));
 assert.equal(JSON.stringify(receipt),before);
});

for(const stage of ['admission','bootstrap','release','generic'])test(stage+' incomplete observation is NOT_TESTED, not differential input',()=>{const r=fixture(stage);delete r.commands['cosign:verify'];const result=evaluate({component:'cosign',status:'success',raw:r});assert.equal(result.decision,null);assert.equal(result.status,'NOT_TESTED');});
test('Cosign missing root evidence is not PASS',()=>assert.equal(evaluate({component:'cosign',status:'success',raw:{}}).decision,null));
test.after(()=>fs.writeFileSync(out+'differential.json',JSON.stringify({records},null,2)));
