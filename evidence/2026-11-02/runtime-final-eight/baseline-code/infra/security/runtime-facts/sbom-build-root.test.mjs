import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {execFileSync} from 'node:child_process';
import {prepareSbomBuildRoot} from './sbom-build-root.mjs';import {sha} from '../summary-v2/codec.mjs';
function fixture(){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'sbom-build-root-unit-')),input=path.join(directory,'input');fs.mkdirSync(path.join(input,'infra/security'),{recursive:true});
 const verifier=fs.readFileSync('infra/security/sbom-verify.mjs');fs.writeFileSync(path.join(input,'infra/security/sbom-verify.mjs'),verifier);fs.writeFileSync(path.join(input,'.git-sha'),'a'.repeat(40));
 fs.mkdirSync(path.join(directory,'infra/security'),{recursive:true});fs.writeFileSync(path.join(directory,'infra/security/sbom-verify.mjs'),verifier);fs.writeFileSync(path.join(directory,'.git-sha'),'a'.repeat(40));
 const archive=path.join(directory,'runtime-sbom-clean-source.tar.gz');execFileSync('tar',['czf',archive,'-C',input,'infra','.git-sha']);
 const manifest={schema:1,commit:'a'.repeat(40),classification:'SYNTHETIC_UNIT_ONLY',archiveSha256:sha(fs.readFileSync(archive)),files:{'infra/security/sbom-verify.mjs':sha(verifier),'.git-sha':sha('a'.repeat(40))}};
 fs.writeFileSync(path.join(directory,'runtime-sbom-clean-source.json'),JSON.stringify(manifest));return {directory,manifest,dispose:()=>fs.rmSync(directory,{recursive:true,force:true})};
}
test('clean build root preserves verifier/commit and removes disposable checkout',()=>{
 const f=fixture();try{const r=prepareSbomBuildRoot(f.directory);assert.equal(fs.readFileSync(path.join(r.directory,'.git-sha'),'utf8'),'a'.repeat(40));assert.equal(r.identity.files,2);r.cleanup();assert.equal(fs.existsSync(r.directory),false);}finally{f.dispose();}
});
test('clean build root rejects altered archive or unsafe manifest before extraction',()=>{
 const f=fixture();try{
  f.manifest.files['../outside']='0'.repeat(64);fs.writeFileSync(path.join(f.directory,'runtime-sbom-clean-source.json'),JSON.stringify(f.manifest));assert.throws(()=>prepareSbomBuildRoot(f.directory),/Unsafe/);
  fs.appendFileSync(path.join(f.directory,'runtime-sbom-clean-source.tar.gz'),'tamper');assert.throws(()=>prepareSbomBuildRoot(f.directory),/identity mismatch/);
 }finally{f.dispose();}
});
