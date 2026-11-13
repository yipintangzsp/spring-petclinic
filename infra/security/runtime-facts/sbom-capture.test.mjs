import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {captureStage} from './execute.mjs';import {createRuntimeOwner} from './owner.mjs';import {digest} from '../summary-v2/codec.mjs';
const command=JSON.parse(fs.readFileSync('resources/security-manager/petclinic-adapter.json')).find(p=>p.id==='sbom').command;
const binding={job:'CONTROLLED_SBOM_COLLECTOR_UNIT',build:1,project:'fixture',source:'c'.repeat(40),candidate:'registry.invalid/fixture@sha256:'+'a'.repeat(64),targetScope:'project',runId:'unit'};
function fixture(generatorStatus=0,mismatch=false){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'sbom-capture-unit-'));fs.mkdirSync(path.join(root,'infra/security'),{recursive:true});fs.mkdirSync(path.join(root,'target/classes/META-INF/sbom'),{recursive:true});
 fs.copyFileSync('infra/security/sbom-verify.mjs',path.join(root,'infra/security/sbom-verify.mjs'));fs.writeFileSync(path.join(root,'.git-sha'),binding.source);
 // This shell replaces Maven only in an explicit UNIT fixture. Live acceptance
 // requires the real Jenkins Maven build; these are not production samples.
 fs.writeFileSync(path.join(root,'mvnw'),'#!/bin/sh\nprintf "CONTROLLED_UNIT_GENERATOR\\n"\nexit '+generatorStatus+'\n',{mode:0o700});
 const bom={bomFormat:'CycloneDX',specVersion:'1.6',components:Array.from({length:10},(_,i)=>({'bom-ref':'ref-'+i,name:'fixture-'+i})),dependencies:[{ref:'ref-0',dependsOn:[]}]};
 const jarRoot=path.join(root,'jar/META-INF/sbom');fs.mkdirSync(jarRoot,{recursive:true});fs.writeFileSync(path.join(jarRoot,'application.cdx.json'),JSON.stringify(bom));
 const z=spawnSync('zip',['-q','-r',path.join(root,'target/spring-petclinic-4.0.0-SNAPSHOT.jar'),'META-INF'],{cwd:path.join(root,'jar')});assert.equal(z.status,0);
 fs.writeFileSync(path.join(root,'target/classes/META-INF/sbom/application.cdx.json'),JSON.stringify({...bom,...(mismatch?{changed:true}:{})}));return root;
}
for(const [name,code,mismatch,expected] of [['positive-native',0,false,'PASS'],['generator-failure',7,false,'FAIL'],['jar-maven-byte-mismatch',0,true,'FAIL']])test('SBOM original parent capture / '+name,async()=>{
 const root=fixture(code,mismatch);try{
  const old=spawnSync('/bin/sh',['-c',command],{cwd:root,encoding:'utf8'});
  const run=await captureStage({sourceId:'sbom',command,binding,cwd:root,env:process.env});
  assert.equal(run.exitStatus,old.status);assert.equal(run.envelope.facts.raw.stage,'production');assert.equal(run.envelope.facts.raw.generator.status,code);
  const before=digest(run.envelope.facts),owner=createRuntimeOwner({binding,directory:path.join(root,'owner')}),r=await owner.accept(run.envelope),g=owner.reuseForGate('sbom',old.status===0?'success':'failed');
  assert.equal(r.result.decision,expected);assert.equal(r.resultDigest,g.resultDigest);assert.equal(owner.snapshot().evaluationCounts.sbom,1);assert.equal(digest(run.envelope.facts),before);
  if(code===0&&!mismatch){assert.equal(run.envelope.reports.length,2);assert.equal(JSON.parse(Buffer.from(run.envelope.facts.raw.extraction.base64,'base64')).components.length,10);}
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('SBOM success stdout without original native observations is FACT_CONTRACT_INCOMPLETE',async()=>{
 const root=fixture();try{fs.writeFileSync(path.join(root,'infra/security/sbom-verify.mjs'),"console.log('success');\n");await assert.rejects(captureStage({sourceId:'sbom',command,binding,cwd:root,env:process.env}),/FACT_CONTRACT_INCOMPLETE/);}finally{fs.rmSync(root,{recursive:true,force:true});}
});
