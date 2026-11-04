// Writes review artifacts only, exclusively into a NEW LOCAL DIRECTORY.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
import {candidatePod,candidateSA,candidateNetworkPolicy,validateCandidate} from './plan.mjs';
export function render(out){
 const docs={'pod.candidate.yaml':candidatePod(),'serviceaccount.candidate.yaml':candidateSA(),'networkpolicy.candidate.yaml':candidateNetworkPolicy()};
 validateCandidate({pod:docs['pod.candidate.yaml'],sa:docs['serviceaccount.candidate.yaml'],networkPolicy:docs['networkpolicy.candidate.yaml']},{reviewOnly:true});
 fs.mkdirSync(out,{recursive:false});
 for(const [name,doc] of Object.entries(docs))fs.writeFileSync(path.join(out,name),JSON.stringify(doc,null,2)+'\n',{flag:'wx'});
 return {created:Object.keys(docs),applied:0,deployable:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 if(process.argv.length!==3)throw Error('One new local output directory required');
 console.log(JSON.stringify(render(path.resolve(process.argv[2]))));
}
