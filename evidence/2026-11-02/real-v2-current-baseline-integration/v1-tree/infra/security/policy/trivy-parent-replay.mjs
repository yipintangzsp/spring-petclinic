// Test-only complete-original-source collector. All external effects are inert.
import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';
import {classifyVulnerability} from '../trivy-medium-policy.mjs';
const clean=p=>fs.readFileSync(p,'utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
const target=clean('infra/security/audit-target.mjs'),ensure=clean('infra/security/ensure-audit-candidate.mjs'),audit=clean('infra/security/audit-trivy.mjs'),publish=clean('infra/observability/publish-artifacts.mjs');
const command='( node infra/security/ensure-audit-candidate.mjs && node infra/security/audit-trivy.mjs )';
export async function replayTrivy(input,stage='parent'){
 async function operation(kind){
  const reports={},observations=[],counts={};let clock=Date.parse('2026-11-01T00:00:00Z'),review,reviewRead=false,copyAttempted=false;
  const tick=key=>key+'#'+(counts[key]=(counts[key]??0)+1);
  const io=(type,path)=>{const key=type+':'+path,n=tick(key),error=input.io[n]??input.io[key];observations.push({type:'io',key,occurrence:n,ok:!error});if(error)throw Error(error);};
  const fsFake={mkdirSync:p=>io('mkdir',p),writeFileSync:(p,v)=>{io('write',p);reports[p]=String(v);},readFileSync:p=>{
   io('read',p);if(p==='.devsecops/sbom.json')return input.sbom;
   if(p==='infra/security/trivy-medium-review.json'){reviewRead=true;try{review=JSON.parse(input.review);}catch{}return input.review;}
   if(p==='target/platform/image-digest.txt')return input.expectedDigest;
   throw Error('Uncaptured file read refused: '+p);
  }};
  function keyFor(url,o){
   if(kind==='ensure-candidate'){
    if(url.includes('harbor-core'))return copyAttempted?'candidate-verified':'candidate-exists';
    return (o.method??'GET')==='PUT'?'candidate-alias':'candidate-source';
   }
   if(url.endsWith('/scan'))return 'scan:'+decodeURIComponent(url.split('/').at(-2));
   if(url.includes('with_scan_overview'))return 'overview:'+decodeURIComponent(url.split('/').at(-1).split('?')[0]);
   if(url.includes('/additions/vulnerabilities'))return 'report:'+decodeURIComponent(url.split('/').at(-3));
   return 'root';
  }
  const fetch=async(url,o={})=>{
   const key=keyFor(url,o),n=tick('http:'+key),rule=input.http[n]??input.http[key];
   let d;
   if(rule)d=structuredClone(rule);
   else if(key==='candidate-source')d={status:200,bytes:input.manifest};
   else if(key==='candidate-alias'||key.startsWith('scan:'))d={status:202,json:{}};
   else if(key.startsWith('overview:'))d={status:200,json:{scan_overview:{trivy:input.scanSummary}}};
   else if(key.startsWith('report:'))d={status:200,json:input.nativeReports[key.slice(7)]??input.defaultNative};
   else if(key==='root')d={status:200,json:input.root};
   else d={status:200,json:{}};
   observations.push({type:'http',key,occurrence:n,url,method:o.method??'GET',headers:structuredClone({...o.headers,Authorization:o.headers?.Authorization?'SYNTHETIC_AUTH_PRESENT':undefined}),result:structuredClone(d)});
   if(d.error){const e=Error(d.error.message??'controlled transport error');e.name=d.error.name??'TypeError';throw e;}
   const body=d.bytes??JSON.stringify(d.json??{});
   return {status:d.status,ok:d.status>=200&&d.status<300,body:{cancel:async()=>{}},arrayBuffer:async()=>Buffer.from(body),json:async()=>{if(d.jsonError)throw Error('controlled malformed JSON');return structuredClone(d.json);}};
  };
  const external=(bin,args,options={},isSpawn=false)=>{
   if(bin==='node')copyAttempted=true;
   const key=bin==='node'?'candidate-copy':args.includes('deploy')?'deployment':args.includes('pods')?'pods':'runtime-maps';
   const rule=input.commands[key];observations.push({type:'command',key,bin,args:[...args],timeout:options.timeout,result:structuredClone(rule??{status:0})});
   if(isSpawn)return structuredClone(rule??{status:0,stdout:'',stderr:''});
   if(rule?.error||rule?.status){const e=Error(rule?.error??'controlled command error');e.code=rule?.code??'ETIMEDOUT';throw e;}
   if(rule&&Object.hasOwn(rule,'stdout'))return rule.stdout;
   if(key==='deployment')return JSON.stringify(input.deployment);
   if(key==='pods')return JSON.stringify({items:input.pods});
   return input.maps;
  };
  class FixedDate extends Date{constructor(...a){super(...(a.length?a:[clock]));}static now(){return clock;}}
  counts['ensure-lookup']=0;
  const ctx={fs:fsFake,crypto,Buffer,URL,Date:FixedDate,AbortSignal:{timeout:ms=>({timeout:ms})},fetch,process:{env:structuredClone(input.env),argv:['node','publish-artifacts.mjs','harbor-scan'],exit:code=>{throw {controlledExit:true,code};}},spawnSync:(...a)=>external(...a,true),execFileSync:(...a)=>external(...a),classifyVulnerability,console:{log:()=>{}},setTimeout:(fn,ms)=>{clock+=ms;queueMicrotask(fn);return 1;},Promise};
  let exitStatus=0,diagnostic;
  try{await vm.runInNewContext('(async()=>{'+target+'\n'+(kind==='ensure-candidate'?ensure:kind==='audit'?audit:publish)+'})()',ctx);}catch(e){exitStatus=e.controlledExit?e.code:1;diagnostic=e.controlledExit?undefined:e.message;}
  let classifierInput;
  if(kind==='audit'&&reviewRead){try{const r=JSON.parse(reports['.devsecops/trivy-audit.json']);classifierInput={findings:r.scans.flatMap(s=>Object.values(s.raw).flatMap(x=>x.vulnerabilities??[])),review,image:r.image};}catch{}}
  return {stage:kind,execution:{exitStatus,...(diagnostic?{diagnostic}:{})},reports,observations,...(classifierInput?{classifierInput}:{})};
 }
 if(stage==='release-scan'){const op=await operation('release-scan');return {schema:1,stage,complete:true,classification:'CONTROLLED_REPLAY',...op};}
 const first=await operation('ensure-candidate'),operations=[first];if(first.execution.exitStatus===0)operations.push(await operation('audit'));
 return {schema:1,stage:'parent',complete:true,classification:'CONTROLLED_REPLAY',command,operations};
}
