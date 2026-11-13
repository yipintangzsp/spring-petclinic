// Disposable clean checkout for the dedicated Maven build. Preserve all tracked
// files and Maven checks; keep only unrelated loose collector files outside it.
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {execFileSync} from 'node:child_process';
import {sha,fail} from '../summary-v2/codec.mjs';
export function prepareSbomBuildRoot(cwd=process.cwd()){
 const manifest=JSON.parse(fs.readFileSync(path.join(cwd,'runtime-sbom-clean-source.json'))),archive=path.join(cwd,'runtime-sbom-clean-source.tar.gz');
 if(manifest.schema!==1||manifest.commit!==fs.readFileSync(path.join(cwd,'.git-sha'),'utf8').trim()||sha(fs.readFileSync(archive))!==manifest.archiveSha256)fail('Clean build input identity mismatch');
 if(manifest.files?.['infra/security/sbom-verify.mjs']!==sha(fs.readFileSync(path.join(cwd,'infra/security/sbom-verify.mjs'))))fail('Frozen SBOM verifier mismatch');
 for(const p of Object.keys(manifest.files))if(p.startsWith('/')||p.split('/').includes('..'))fail('Unsafe clean build path');
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'runtime-sbom-build-'));
 try{
  execFileSync('tar',['xzf',archive,'-C',directory],{timeout:30000});
  for(const [p,h] of Object.entries(manifest.files)){
   if(p.startsWith('/')||p.split('/').includes('..'))fail('Unsafe clean build path');
   const file=path.join(directory,p);if(!fs.lstatSync(file).isFile()||sha(fs.readFileSync(file))!==h)fail('Clean build source hash mismatch: '+p);
  }
  return {directory,identity:{classification:manifest.classification,commit:manifest.commit,archiveSha256:manifest.archiveSha256,files:Object.keys(manifest.files).length},cleanup:()=>fs.rmSync(directory,{recursive:true,force:true})};
 }catch(e){fs.rmSync(directory,{recursive:true,force:true});throw e;}
}
