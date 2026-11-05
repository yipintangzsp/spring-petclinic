// Explicit MOCK protocol entry only. Real endpoints/IDs/token values are not CLI options.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {routeResultsHttp} from '../router.mjs';
import {createHttpTransport} from './dojo-http.mjs';
export function httpArguments(argv){
 const a={};for(let i=0;i<argv.length;i+=2){const k=argv[i];if(!['--artifact','--seal-digest','--output','--journal','--enable-mock-http','--target','--credential-file'].includes(k)||!argv[i+1]||Object.hasOwn(a,k))throw Error('INVALID_MOCK_HTTP_ARGUMENT');a[k]=argv[i+1];}
 if(Object.keys(a).length!==7||a['--enable-mock-http']!=='true'||!/^[a-f0-9]{64}$/.test(a['--seal-digest']))throw Error('EXPLICIT_MOCK_HTTP_OPT_IN_REQUIRED');return a;
}
export async function main(argv=process.argv.slice(2)){
 const a=httpArguments(argv),dir=path.resolve(a['--artifact']);
 const transport=createHttpTransport({enabled:true,targetId:a['--target'],credentialFile:path.resolve(a['--credential-file'])});
 const summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json')));
 const r=await routeResultsHttp({run:{summary},artifactDirectory:dir,expectedSealDigest:a['--seal-digest'],output:path.resolve(a['--output']),journalDirectory:path.resolve(a['--journal']),transport});
 console.log(JSON.stringify({classification:'LOCAL_MOCK_HTTP_NOT_REAL_DOJO_DELIVERY',...r}));return r.candidateDeliveryAllowed?0:1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{process.exitCode=await main();}catch{console.error('MOCK_HTTP_CONSUMER_REJECTED');process.exitCode=2;}}
