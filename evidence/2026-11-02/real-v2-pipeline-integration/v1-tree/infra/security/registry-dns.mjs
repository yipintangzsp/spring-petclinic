// Publish only the existing private Harbor name through CoreDNS's supported custom-zone mount.
import fs from 'node:fs';
import dns from 'node:dns/promises';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {read,kube,requireLease} from './scanner-runtime.mjs';
const key='platform-harbor.server',marker='# Managed by platform-harbor-dns; existing Harbor service only';
export function harborZone(ip){
 if(net.isIP(ip)!==4)throw Error('Existing Harbor IPv4 ClusterIP required');
 return `${marker}\ncore.harbor.domain:53 {\n    errors\n    hosts {\n        ${ip} core.harbor.domain\n        ttl 60\n    }\n}\n`;
}
export function foreignZones(data){return Object.fromEntries(Object.entries(data??{}).filter(([name])=>name!==key));}
async function main(){
 requireLease();
 const service=read(['-n','harbor','get','service','harbor-core']);
 const cm=read(['-n','kube-system','get','configmap','coredns-custom']);
 const previous=cm.data?.[key];if(previous&&!previous.startsWith(marker+'\n'))throw Error('Foreign DNS zone preserved');
 const desired=harborZone(service.spec.clusterIP);
 const report={status:'failed',source:fs.readFileSync('.git-sha','utf8').trim(),serviceUid:service.metadata.uid,address:service.spec.clusterIP,configmapUid:cm.metadata.uid,key,previous:previous??null,startedAt:new Date().toISOString()};
 try{
  kube(['apply','--server-side','--field-manager=platform-harbor-dns','-f','-'],JSON.stringify({apiVersion:'v1',kind:'ConfigMap',metadata:{name:'coredns-custom',namespace:'kube-system'},data:{[key]:desired}}));
  const after=read(['-n','kube-system','get','configmap','coredns-custom']);
  if(after.metadata.uid!==cm.metadata.uid||after.data?.[key]!==desired||!isDeepStrictEqual(foreignZones(after.data),foreignZones(cm.data)))throw Error('Unexpected shared DNS configuration change');
  report.otherZonesPreserved=true;
  for(let i=0;i<60;i++){
   try{const answers=await dns.lookup('core.harbor.domain',{all:true});if(answers.some(x=>x.address===service.spec.clusterIP)){report.resolved=answers;report.status='success';break;}}catch(e){report.lastLookupError=e.code;}
   await new Promise(r=>setTimeout(r,2000));
  }
  if(report.status!=='success')throw Error('Harbor internal DNS did not reload within bounded wait');
 }finally{report.finishedAt=new Date().toISOString();fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/registry-dns.json',JSON.stringify(report,null,2));}
 console.log('Existing Harbor name resolves to its service ClusterIP; unrelated DNS zones preserved');
}
if(process.argv[1]===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
