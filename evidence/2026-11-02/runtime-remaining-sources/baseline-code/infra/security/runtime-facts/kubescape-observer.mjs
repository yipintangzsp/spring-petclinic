// Passive observer of the unchanged, least-privilege Kubescape audit command.
// Native report bytes are kept in memory; neither token nor raw payload is archived.
import fs from 'node:fs';import cp from 'node:child_process';import crypto from 'node:crypto';import {syncBuiltinESMExports} from 'node:module';
if(process.env.RUNTIME_FACT_SOURCE==='kubescape'&&process.argv[1]?.endsWith('/governance/kubescape.mjs')){
 const orig={read:fs.readFileSync,write:fs.writeFileSync,mkdir:fs.mkdirSync,mkdtemp:fs.mkdtempSync,chmod:fs.chmodSync,rm:fs.rmSync,spawn:cp.spawnSync};
 const raw={holder:process.env.HEAVY_HOLDER||'jenkins-petclinic-'+process.env.BUILD_NUMBER,observations:{hashes:{},scans:[]}},o=raw.observations,events=[];let temp;
 const sha=v=>crypto.createHash('sha256').update(v).digest('hex'),str=v=>v==null?'':String(v);
 const observe=fn=>{try{fn();}catch(e){events.push({kind:'OBSERVER_ERROR',errorClass:e.name});}};
 fs.readFileSync=function(p,...args){
  try{const value=orig.read(p,...args);observe(()=>{const n=String(p);
   if(n==='infra/security/governance/tools-lock.json'){raw.lock=JSON.parse(str(value)).kubescape;o.lockReadSucceeded=true;}
   if(n==='.git-sha')o.sourceReadSucceeded=true;
   if(raw.lock&&(n===raw.lock.path||n.startsWith(raw.lock.artifactRoot+'/')))o.hashes[n]={value:sha(value)};
   const scan=o.scans.find(s=>s.output===n);if(scan){scan.report={value:str(value)};scan.hash={value:sha(value)};}
  });return value;}catch(e){observe(()=>{const n=String(p);
   if(n==='infra/security/governance/tools-lock.json')o.lockReadSucceeded=false;
   if(n==='.git-sha')o.sourceReadSucceeded=false;
   o.hashes[n]={error:e.code??e.name};const scan=o.scans.find(s=>s.output===n);if(scan)scan.report={error:e.code??e.name};
  });throw e;}
 };
 fs.mkdirSync=function(p,...args){let success=false;try{const r=orig.mkdir(p,...args);success=true;return r;}finally{if(String(p)==='.devsecops/kubescape')o.outputDirSucceeded=success;}};
 fs.mkdtempSync=function(p,...args){let success=false;try{const r=orig.mkdtemp(p,...args);success=true;temp=r;return r;}finally{o.tempCreateSucceeded=success;}};
 fs.chmodSync=function(p,...args){let success=false;try{const r=orig.chmod(p,...args);success=true;return r;}finally{if(String(p)===temp)o.tempChmodSucceeded=success;}};
 fs.writeFileSync=function(p,...args){let success=false;try{const r=orig.write(p,...args);success=true;return r;}finally{
  const n=String(p);if(temp&&n===temp+'/config')o.configWriteSucceeded=success;
  if(n==='.devsecops/kubescape-gate.json')o.finalReportWriteSucceeded=success;
  const scan=o.scans.find(s=>s.output+'.log'===n);if(scan)scan.logWriteSucceeded=success;
 }};
 fs.rmSync=function(p,...args){let success=false;try{const r=orig.rm(p,...args);success=true;return r;}finally{if(String(p)===temp)o.cleanupSucceeded=success;}};
 cp.spawnSync=function(bin,args,options){const startedAtMs=Date.now(),r=orig.spawn(bin,args,options),completedAtMs=Date.now();observe(()=>{
  const v={status:r.status,stdout:str(r.stdout),stderr:str(r.stderr),error:r.error?{code:r.error.code??r.error.name}:null};
  events.push({kind:'command',bin:String(bin),argv:[...args],startedAtMs,completedAtMs,exitStatus:r.status,stdoutSha256:sha(v.stdout),stderrSha256:sha(v.stderr),errorClass:v.error?.code??null});
  if(String(bin)===raw.lock?.path){o.scans.push({output:args[args.indexOf('--output')+1],command:v});return;}
  if(bin!=='kubectl')return;
  if(args.includes('lease'))o.lease=v;
  else if(args.includes('config')&&args.includes('view'))o.server=v;
  else if(args.includes('configmap'))o.ca=v;
  else if(args.includes('create')&&args.includes('token'))o.token=v;
  else if(args.includes('can-i')&&args.includes('secrets'))o.secretReadCheck=v;
  else if(args.includes('can-i')&&args.includes('deployments'))o.businessWriteCheck=v;
 });return r;};
 syncBuiltinESMExports();process.on('exit',exitStatus=>{try{orig.write(3,JSON.stringify({schema:1,sourceId:'kubescape',exitStatus,adapterPayload:raw,events})+'\n');}catch{process.exitCode=process.exitCode||74;}});
}
