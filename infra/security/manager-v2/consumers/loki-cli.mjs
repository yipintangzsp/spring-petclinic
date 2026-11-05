// Local-only entry. No production URLs, tokens, scanners, Policy calls or config.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
import {prepareLoki,publishLoki,createLokiTransport} from './loki.mjs';
export function lokiArguments(argv){
 const allowed=['artifact','seal','project','output','mock-http'],r={};for(let i=0;i<argv.length;i++){const k=argv[i]?.replace(/^--/,'');if(!allowed.includes(k)||Object.hasOwn(r,k))throw Error('INVALID_LOKI_ARGUMENT');if(k==='mock-http')r[k]=true;else{const v=argv[++i];if(!v||v.startsWith('--'))throw Error('MISSING_LOKI_ARGUMENT');r[k]=v;}}
 for(const k of ['artifact','seal','project','output'])if(!r[k])throw Error('MISSING_LOKI_ARGUMENT');return r;
}
export async function main(argv){const a=lokiArguments(argv),dir=path.resolve(a.artifact),summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json'))),plan=prepareLoki({run:{summary},artifactDirectory:dir,expectedSealDigest:a.seal,expectedProjectId:a.project});return publishLoki(plan,{output:path.resolve(a.output),transport:createLokiTransport(a['mock-http']?{mode:'mock-http',targetId:'loki-loopback-v1'}:{})});}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main(process.argv.slice(2)).then(x=>{process.stdout.write(JSON.stringify(x)+'\n');if(!['DRY_RUN','ACKNOWLEDGED'].includes(x.deliveryState))process.exitCode=1;},()=>{process.stderr.write('LOKI_CANDIDATE_REJECTED\n');process.exitCode=1;});
