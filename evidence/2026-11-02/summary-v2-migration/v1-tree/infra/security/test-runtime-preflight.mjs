import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
export const expectedId='sha256:8fb11c38b3551e22d50adbb688f027f8ff4ea2d2445aa277c1cc97b4af85ec54';
export function validateTestRuntime(info){
 if(info.Id!==expectedId||info.Architecture!=='arm64'||info.Os!=='linux')throw Error('MySQL test image differs from reviewed ARM64 digest');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const docker=(args,allowed=[0],timeout=30000)=>{const r=spawnSync('docker',args,{encoding:'utf8',timeout,maxBuffer:1024*1024});if(r.error||!allowed.includes(r.status))throw Error('Test runtime preparation failed: '+String(r.stderr).slice(-800));return r;};
 const before=docker(['image','inspect','mysql:9.7'],[0,1]);
 if(before.status!==0){
  const pinned='mysql@'+expectedId;
  docker(['pull','--platform','linux/arm64',pinned],[0],180000);
  validateTestRuntime(JSON.parse(docker(['image','inspect',pinned]).stdout)[0]);
  docker(['tag',pinned,'mysql:9.7']);
 }
 const info=JSON.parse(docker(['image','inspect','mysql:9.7']).stdout)[0];validateTestRuntime(info);
 fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/test-runtime.json',JSON.stringify({status:'success',image:'mysql:9.7',digest:expectedId,architecture:info.Architecture,cacheHit:before.status===0,preparedBeforeTestJVM:true},null,2));
 console.log('Pinned MySQL test runtime prepared before Maven/test JVMs');
}
