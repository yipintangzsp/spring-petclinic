// Offline artifact consumption only. No tool execution, Policy evaluation or API.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
import {digest} from '../../summary-v2/codec.mjs';import {routeResults} from '../router.mjs';import {DEFINITION} from './defectdojo.mjs';
export function argumentsOf(argv){const o={};for(let i=0;i<argv.length;i+=2){const k=argv[i];if(!['--artifact','--seal-digest','--output'].includes(k)||!argv[i+1]||Object.hasOwn(o,k))throw Error('INVALID_OFFLINE_ARGUMENT');o[k]=argv[i+1];}if(Object.keys(o).length!==3||!/^[a-f0-9]{64}$/.test(o['--seal-digest']))throw Error('INVALID_OFFLINE_ARGUMENT');return o;}
export function main(argv=process.argv.slice(2)){
 const o=argumentsOf(argv),dir=path.resolve(o['--artifact']),output=path.resolve(o['--output']),summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json')));
 const result=routeResults({run:{summary},artifactDirectory:dir,expectedSealDigest:o['--seal-digest'],output,definitions:[DEFINITION]});
 console.log(JSON.stringify({classification:'OFFLINE_CANDIDATE_PAYLOAD_PREPARATION_NOT_HTTP_DELIVERY',summaryDigest:digest(summary),...result}));return result.candidateDeliveryAllowed?0:1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{process.exitCode=main();}catch{console.error('OFFLINE_CONSUMER_INPUT_REJECTED');process.exitCode=2;}}
