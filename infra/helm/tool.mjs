import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import crypto from 'node:crypto';import {spawnSync} from 'node:child_process';
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
export function platformKey(system=os.platform(),arch=os.arch()){if(!['darwin','linux'].includes(system)||!['arm64','x64'].includes(arch))throw Error('Unsupported Helm platform');return system+'-'+(arch==='x64'?'amd64':'arm64');}
export function ensureHelm(){const lock=JSON.parse(fs.readFileSync('infra/helm/tools-lock.json')),key=platformKey(),entry=lock.platforms[key];if(!entry)throw Error('Unpinned Helm platform');const root=path.resolve('.tools/helm/'+lock.helmVersion+'/'+key),bin=root+'/helm';fs.mkdirSync(root,{recursive:true});
 if(fs.existsSync(bin)){if(hash(fs.readFileSync(bin))!==entry.binarySha256)throw Error('Cached Helm binary changed');return bin;}
 const archive=path.resolve('.tools/helm-downloads/'+path.basename(new URL(entry.url).pathname));fs.mkdirSync(path.dirname(archive),{recursive:true});
 if(!fs.existsSync(archive)){const args=['-fLsS','--connect-timeout','8','--max-time','180'];if(process.env.HELM_DOWNLOAD_PROXY)args.push('--proxy',process.env.HELM_DOWNLOAD_PROXY);else args.push('--noproxy','*');args.push(entry.url,'-o',archive);const r=spawnSync('curl',args,{encoding:'utf8',timeout:190000});if(r.status!==0)throw Error('Pinned Helm download failed');}
 if(hash(fs.readFileSync(archive))!==entry.archiveSha256)throw Error('Official Helm archive checksum mismatch');const extract=spawnSync('tar',['-xzf',archive,'-O',key+'/helm'],{maxBuffer:64*1024*1024});if(extract.status!==0||hash(extract.stdout)!==entry.binarySha256)throw Error('Helm binary identity mismatch');fs.writeFileSync(bin,extract.stdout,{mode:0o755,flag:'wx'});return bin;
}
if(process.argv[1]?.endsWith('/tool.mjs'))console.log(ensureHelm());
