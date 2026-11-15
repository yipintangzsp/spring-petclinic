import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {helmBindingFromShadow} from './helm-binding.mjs';
import {approvedRelease,validateHelmBinding} from './contract.mjs';

const digest='sha256:'+'a'.repeat(64);
const valuesText='# fixture\nimage:\n  digest: '+digest+'\n';
const rendered='apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: petclinic\n';
const renderedHash=crypto.createHash('sha256').update(rendered).digest('hex');
const valuesHash='sha256:'+crypto.createHash('sha256').update(valuesText).digest('hex');
const valuesHashHex=crypto.createHash('sha256').update(valuesText).digest('hex');
const chartText=v=>'apiVersion: v2\nname: petclinic\nversion: '+v+'\n';

function fixture(t,{status,chartVersion='0.1.0',build='13',omitFingerprints=false}={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'helm-binding-'));
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.mkdirSync(dir+'/charts/petclinic',{recursive:true});
 const chart=chartText(chartVersion);
 fs.writeFileSync(dir+'/charts/petclinic/Chart.yaml',chart);
 fs.writeFileSync(dir+'/charts/petclinic/values-prod.yaml',valuesText);
 if(status!==null){
  fs.mkdirSync(dir+'/.helm-shadow',{recursive:true});
  fs.writeFileSync(dir+'/.helm-shadow/rendered.yaml',rendered);
  const base={schemaVersion:1,validationBuild:build,mode:'SHADOW_ONLY',HELM_RENDER_STATUS:'PASS',renderedSha256:renderedHash};
  if(!omitFingerprints){base.chartSha256=crypto.createHash('sha256').update(chart).digest('hex');base.valuesSha256=valuesHashHex;}
  fs.writeFileSync(dir+'/.helm-shadow/status.json',JSON.stringify({...base,...status}));
 }
 const prev=process.cwd();process.chdir(dir);t.after(()=>process.chdir(prev));
 return dir;
}

test('no shadow products: legacy approval path returns null',t=>{
 fixture(t,{status:null});
 assert.equal(helmBindingFromShadow({BUILD_NUMBER:'13'}),null);
});

test('binding is assembled from shadow products and validates end to end',t=>{
 fixture(t,{});
 const binding=helmBindingFromShadow({BUILD_NUMBER:'13'});
 assert.deepEqual(binding,{chart:'petclinic',valuesFile:'charts/petclinic/values-prod.yaml',chartVersion:'0.1.0',valuesSha256:valuesHash});
 const gate={result:'SUCCESS',build:13,source:'b'.repeat(40),candidate:'core.harbor.domain/petclinic/petclinic@'+digest,trivy:{status:'success',targetScope:'candidate',auditTargetImage:'core.harbor.domain/petclinic/petclinic@'+digest,runtimeImage:'core.harbor.domain/petclinic/petclinic@'+digest,scans:[{digest:'c'.repeat(64)},{digest:'d'.repeat(64)}]},summary:{auditTargetImage:'core.harbor.domain/petclinic/petclinic@'+digest,targetScope:'candidate',source:'b'.repeat(40),build:13,trivy_critical:0,trivy_high:0},sourceScan:{status:'success'},admission:{status:'success'},semgrep:{status:'success'},zap:{status:'success'},falco:{status:'success'},dojo:{status:'success'},kubescape:{status:'success'},business:{unchanged:true},sbom:{candidate:'core.harbor.domain/petclinic/petclinic@'+digest,architectures:[{arch:'amd64',jarSha256:'sha256:'+'e'.repeat(64),sbomSha256:'sha256:'+'f'.repeat(64)},{arch:'arm64',jarSha256:'sha256:'+'e'.repeat(64),sbomSha256:'sha256:'+'f'.repeat(64)}]}};
 const signing={images:[digest,'c'.repeat(64),'d'.repeat(64)].map(d=>({image:'core.harbor.domain/petclinic/petclinic@'+d,verified:true}))};
 const approved=approvedRelease(gate,signing,binding);
 assert.deepEqual(approved.helm,binding);
 assert.equal(validateHelmBinding(approved,{chartVersion:'0.1.0',valuesSha256:valuesHash}),binding);
 assert.throws(()=>validateHelmBinding(approved,{chartVersion:'0.1.1',valuesSha256:valuesHash}),/differ from approved binding/);
});

test('stale shadow products from another build are refused',t=>{
 fixture(t,{});
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'14'}),/another build/);
});

test('failed render or tampered output is refused',t=>{
 fixture(t,{status:{HELM_RENDER_STATUS:'FAIL'}});
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'13'}),/unusable/);
});

test('tampered rendered output is refused',t=>{
 const dir=fixture(t,{});
 fs.appendFileSync(dir+'/.helm-shadow/rendered.yaml','# tampered\n');
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'13'}),/differs from Gate record/);
});

test('shadow products without validationBuild are refused',t=>{
 fixture(t,{status:{validationBuild:undefined}});
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'13'}),/build identity missing/);
});

test('missing BUILD_NUMBER is refused when shadow products exist',t=>{
 fixture(t,{});
 assert.throws(()=>helmBindingFromShadow({}),/build identity missing/);
});

test('values changed after the render are refused',t=>{
 const dir=fixture(t,{});
 fs.writeFileSync(dir+'/charts/petclinic/values-prod.yaml',valuesText.replace('a'.repeat(64),'b'.repeat(64)));
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'13'}),/render inputs differ/);
});

test('chart version changed after the render is refused',t=>{
 const dir=fixture(t,{});
 fs.writeFileSync(dir+'/charts/petclinic/Chart.yaml',chartText('0.2.0'));
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'13'}),/render inputs differ/);
});

test('legacy shadow products without input fingerprints are refused',t=>{
 fixture(t,{omitFingerprints:true});
 assert.throws(()=>helmBindingFromShadow({BUILD_NUMBER:'13'}),/lack render input fingerprints/);
});

test('sign-approve assembles the helm binding before any cosign signing',()=>{
 const src=fs.readFileSync(new URL('./sign-approve.mjs',import.meta.url),'utf8');
 const bindingAt=src.indexOf('const helmBinding=helmBindingFromShadow();');
 const signAt=src.indexOf("cosign(['sign'");
 assert.ok(bindingAt>=0,'sign-approve must assemble the binding up front');
 assert.ok(signAt>bindingAt,'binding assembly must precede the first cosign sign');
 assert.ok(!src.includes('approvedRelease(x,report,helmBindingFromShadow())'),'approvedRelease must consume the pre-assembled binding');
});
