import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {evaluate} from './engine.mjs';import {base,sha,read,bom,summary,genericBom,fixture,changeBom,config,oracle,shellOracle} from './sbom-test-harness.mjs';
const records=[];
function run(stage,name,change,want,branch){test(stage+' complete SBOM '+name,async()=>{
 const raw=fixture(stage);change(raw);const before=JSON.stringify(raw),old=await oracle(raw),p=evaluate({component:'sbom',status:'success',raw});assert.equal(old.decision,want,'old: '+old.reason);assert.equal(p.decision,old.decision,'policy: '+p.reason);assert.equal(p.securityLevel,'standard');assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);assert.deepEqual(p.trace,old.trace);
 if(want==='PASS'){const actual=JSON.parse(old.writes[stage==='generic'?'.devsecops/sbom-manager.json':'.devsecops/sbom-summary.json']);assert.deepEqual(p.report,actual);}
 let shell;if(stage==='production'){shell=shellOracle(raw.generator.status,old.code);assert.equal(shell.code===0?'PASS':'FAIL',want);assert.equal(shell.trace.length,raw.generator.status===0?2:1);}
 records.push({stage,name,branch,classification:'CONTROLLED_REPLAY',oldDecision:old.decision,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),diagnostic:old.reason,productionShell:shell});fs.writeFileSync(base+'fixtures/'+stage+'--'+name+'.json',JSON.stringify(raw,null,2));
});}
for(const stage of ['standalone','production','generic']){
 run(stage,'historical-valid',()=>{},'PASS','positive');
 run(stage,'source-file-missing',r=>r.files['.git-sha']={error:'ENOENT'},'FAIL','missing');
 if(stage==='generic'){
  run(stage,'native-report-write-failure',r=>r.io['native-write']={error:'ENOSPC'},'FAIL','io');
  run(stage,'manager-report-write-failure',r=>r.io['manager-report-write']={error:'ENOSPC'},'FAIL','io');
  run(stage,'SBOM-file-missing',r=>r.files['/fixture/project/bom.json']={error:'ENOENT'},'FAIL','missing');
  run(stage,'malformed-JSON',r=>r.files['/fixture/project/bom.json'].value='{','FAIL','malformed');
  run(stage,'config-malformed',r=>r.files['.devsecops/manager-config.json'].value='{','FAIL','malformed');
  run(stage,'source-outside-checkout',r=>config(r,c=>c.sbomFile='../outside.json'),'FAIL','binding');
  for(const key of ['manifestReadError','lockReadError'])run(stage,key,r=>r.runtime[key]='ENOENT','FAIL','prerequisite');
  run(stage,'manifest-hash-mismatch',r=>r.runtime.expectedManifestSha256='bad','FAIL','prerequisite');
  run(stage,'lease-unowned',r=>r.runtime.lease.stdout=JSON.stringify({spec:{holderIdentity:'foreign'}}),'FAIL','prerequisite');
  run(stage,'lease-query-failed',r=>r.runtime.lease={status:1,stdout:'',stderr:'offline'},'FAIL','infrastructure');
  run(stage,'lease-malformed',r=>r.runtime.lease.stdout='{','FAIL','malformed');
  run(stage,'audit-execution-error-is-FAIL',r=>{config(r,c=>c.mode='audit');r.files['/fixture/project/bom.json']={error:'ENOENT'};},'FAIL','audit-semantics');
  run(stage,'historical-generic-1.5-empty-inventory',r=>r.files['/fixture/project/bom.json'].value=genericBom,'PASS','historical-generic');
 }else{
  for(const [name,error]of [['unzip-unavailable','ENOENT'],['extraction-timeout','ETIMEDOUT'],['jar-missing','missing JAR'],['jar-entry-missing','missing ZIP entry']])run(stage,name,r=>r.extraction={status:1,error},'FAIL','extraction');
  run(stage,'Maven-SBOM-file-missing',r=>r.files['target/classes/META-INF/sbom/application.cdx.json']={error:'ENOENT'},'FAIL','missing');
  run(stage,'packaged-Maven-byte-mismatch',r=>r.files['target/classes/META-INF/sbom/application.cdx.json'].value=Buffer.from('other bytes').toString('base64'),'FAIL','binding');
  for(const k of ['output-mkdir','sbom-write','summary-write'])run(stage,'IO-'+k,r=>r.io[k]={error:'ENOSPC'},'FAIL','io');
  run(stage,'malformed-JSON',r=>{r.extraction.base64=Buffer.from('{').toString('base64');r.files['target/classes/META-INF/sbom/application.cdx.json'].value=r.extraction.base64;},'FAIL','malformed');
 }
 for(const [name,change,prod,generic]of [
  ['wrong-format',b=>b.bomFormat='SPDX','FAIL','FAIL'],['version-1.5',b=>b.specVersion='1.5','FAIL','PASS'],['version-missing',b=>delete b.specVersion,'FAIL','PASS'],['components-missing',b=>delete b.components,'FAIL','FAIL'],['components-object',b=>b.components={},'FAIL','FAIL'],['empty-components',b=>b.components=[],'FAIL','PASS'],['nine-components',b=>b.components=b.components.slice(0,9),'FAIL','PASS'],['ten-components',b=>b.components=b.components.slice(0,10),'PASS','PASS'],['count-not-fixed-143',b=>b.components.pop(),'PASS','PASS'],['dependencies-missing',b=>delete b.dependencies,'FAIL','PASS'],['empty-dependencies',b=>b.dependencies=[],'FAIL','PASS'],['duplicate-bom-ref',b=>b.components[1]['bom-ref']=b.components[0]['bom-ref'],'FAIL','PASS'],['missing-bom-ref',b=>delete b.components[0]['bom-ref'],'FAIL','PASS'],['null-component',b=>b.components[0]=null,'FAIL','PASS'],['metadata-missing-no-added-rule',b=>delete b.metadata,'PASS','PASS'],['unresolved-dependency-ref-no-added-rule',b=>b.dependencies[0].ref='absent-component','PASS','PASS'],['package-identity-change-no-risk-inference',b=>b.components[0].name='synthetic-different-package','PASS','PASS'],
 ])run(stage,name,r=>changeBom(r,change),stage==='generic'?generic:prod,'inventory');
 run(stage,'source-label-does-not-add-checkout-validation',r=>r.files['.git-sha'].value='other-source','PASS','existing-no-source-attestation');
}
for(const status of [1,2,127,137,143])run('production','generator-exit-'+status,r=>r.generator={status,stderr:'controlled generator failure'},'FAIL','generation');
run('generic','build-label-not-new-inventory-binding',r=>config(r,c=>c.build=999),'PASS','existing-no-image-attestation');
run('generic','image-config-not-used-by-SBOM',r=>config(r,c=>c.image='registry.example/other@sha256:'+'a'.repeat(64)),'PASS','existing-no-image-attestation');
test('historical 270 BOM summary count/hash and component metadata unchanged',()=>{assert.equal(sha(bom),summary.sha256);const b=JSON.parse(bom);assert.equal(b.components.length,143);assert.equal(b.dependencies.length,144);assert.equal(b.specVersion,'1.6');});
for(const stage of ['production','standalone','generic'])test(stage+' uncaptured facts are NOT_TESTED',()=>{const r=fixture(stage);delete r.io[stage==='generic'?'manager-report-write':'sbom-write'];const p=evaluate({component:'sbom',status:'success',raw:r});assert.equal(p.decision,null);assert.equal(p.status,'NOT_TESTED');});
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({records},null,2)));
for(const stage of ['standalone','production','generic']){
 run(stage,'empty-byte-file',r=>{r.extraction.base64='';r.files['target/classes/META-INF/sbom/application.cdx.json'].value='';r.files['/fixture/project/bom.json'].value='';},'FAIL','malformed');
 run(stage,'JSON-null-file',r=>{r.extraction.base64=Buffer.from('null').toString('base64');r.files['target/classes/META-INF/sbom/application.cdx.json'].value=r.extraction.base64;r.files['/fixture/project/bom.json'].value='null';},'FAIL','malformed');
 run(stage,'arbitrary-vulnerability-property-is-not-scanner-result',r=>changeBom(r,b=>b.vulnerabilities=[{id:'SYNTHETIC',ratings:[{severity:'critical'}]}]),'PASS','inventory-not-vulnerability');
 run(stage,'empty-source-label-no-added-identity-rule',r=>r.files['.git-sha'].value='','PASS','existing-no-source-attestation');
}
for(const stage of ['standalone','production']){
 run(stage,'valid-JSON-whitespace-byte-mismatch',r=>r.files['target/classes/META-INF/sbom/application.cdx.json'].value=Buffer.from(Buffer.from(r.extraction.base64,'base64').toString()+'\n').toString('base64'),'FAIL','binding');
 run(stage,'negative-component-threshold-count',r=>changeBom(r,b=>b.components=[{}]),'FAIL','inventory');
 run(stage,'non-array-dependencies-current-length-semantics',r=>changeBom(r,b=>b.dependencies='x'),'PASS','existing-parser-semantics');
 run(stage,'missing-package-entry-bytes',r=>r.extraction={status:1},'FAIL','extraction');
}
run('generic','source-root-is-not-a-file',r=>config(r,c=>c.sbomFile='.'),'FAIL','binding');
run('generic','absent-SBOM-config-path',r=>config(r,c=>delete c.sbomFile),'FAIL','missing');
run('generic','configuration-file-missing',r=>r.files['.devsecops/manager-config.json']={error:'ENOENT'},'FAIL','missing');
run('generic','manifest-malformed',r=>r.runtime.manifest='{','FAIL','malformed');
run('generic','audit-inventory-success-not-WARN',r=>config(r,c=>c.mode='audit'),'PASS','audit-semantics');
test('missing extraction exit observation is NOT_TESTED',()=>{const r=fixture('standalone');delete r.extraction.status;assert.equal(evaluate({component:'sbom',status:'success',raw:r}).status,'NOT_TESTED');});
test('low/strict/override cannot reinterpret SBOM inventory as risk',async()=>{
 const r=fixture('standalone');r.extraction.status=1;for(const c of [{securityLevel:'low'},{securityLevel:'strict'},{mode:'audit',componentOverrides:{sbom:{Critical:'PASS'}}}])assert.equal(evaluate({component:'sbom',status:'success',raw:r},c).decision,'FAIL');
});
