import fs from 'node:fs';import crypto from 'node:crypto';import {spawnSync} from 'node:child_process';import {promotionInput} from '../security/promotion/contract.mjs';
export function updateDigest(text,approvedDigest,approval){
 if(!/^sha256:[a-f0-9]{64}$/.test(approvedDigest)||approval?.approvedDigest!==approvedDigest)throw Error('Explicit approved digest and approval required');
 const lines=text.split('\n'),start=lines.findIndex(l=>/^image:\s*$/.test(l));if(start<0)throw Error('image mapping required');let end=start+1;while(end<lines.length&&(!/^\S/.test(lines[end])||lines[end].startsWith('#')))end++;
 const matches=[];for(let i=start+1;i<end;i++)if(/^  digest:/.test(lines[i]))matches.push(i);if(matches.length!==1)throw Error('Exactly one image.digest required');const i=matches[0],m=lines[i].match(/^(  digest:\s*)(['"]?)(sha256:[a-f0-9]{64})\2(\s*(?:#.*)?)$/);if(!m)throw Error('Existing immutable digest required');
 promotionInput(approval,'image: core.harbor.domain/petclinic/petclinic@'+m[3]);lines[i]=m[1]+m[2]+approvedDigest+m[2]+m[4];return lines.join('\n');
}
if(process.argv[1]?.endsWith('/update-image-digest.mjs')){
 const [input,output,digest,approvalPath,signature]=process.argv.slice(2);if(!input||!output||!approvalPath||!signature||input===output)throw Error('Fixture/candidate output and signed approval required; never writes input in place');
 const tools=JSON.parse(fs.readFileSync('infra/security/scanner-tools.json')),lock=tools.files.find(x=>x.path==='cosign'),bin=tools.root+'/cosign';if(crypto.createHash('sha256').update(fs.readFileSync(bin)).digest('hex')!==lock.sha256)throw Error('Frozen Cosign tool mismatch');
 const r=spawnSync(bin,['verify-blob','--key','infra/security/cosign.pub','--insecure-ignore-tlog=true','--signature',signature,approvalPath],{encoding:'utf8',timeout:60000});if(r.status!==0)throw Error('Signed approved-release verification failed');
 const before=fs.readFileSync(input,'utf8'),after=updateDigest(before,digest,JSON.parse(fs.readFileSync(approvalPath)));fs.writeFileSync(output,after,{flag:'wx'});console.log(JSON.stringify({changedField:'image.digest',approvedDigest:digest,diff:{before:before.split('\n').find(l=>/^  digest:/.test(l)),after:after.split('\n').find(l=>/^  digest:/.test(l))},gitPush:false,productionMutation:false}));
}
