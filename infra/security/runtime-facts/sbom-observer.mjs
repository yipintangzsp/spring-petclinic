// Passive capture of the unchanged sbom-verify.mjs I/O. No decision or extra
// validator: native bytes are passed unchanged to the existing frozen adapter.
import fs from 'node:fs';import cp from 'node:child_process';import crypto from 'node:crypto';import {syncBuiltinESMExports} from 'node:module';
if(process.env.RUNTIME_FACT_SOURCE==='sbom'&&process.argv[1]?.endsWith('/sbom-verify.mjs')){
 const orig={read:fs.readFileSync,write:fs.writeFileSync,mkdir:fs.mkdirSync,exec:cp.execFileSync};
 const raw={stage:'production',files:{},io:{},now:Date.now()},events=[],reports=[];
 const sha=b=>crypto.createHash('sha256').update(b).digest('hex'),observe=fn=>{try{fn();}catch(e){events.push({kind:'OBSERVER_ERROR',errorClass:e.name});}};
 fs.readFileSync=function(p,...args){try{const v=orig.read(p,...args);observe(()=>{
  const name=String(p);if(name==='target/classes/META-INF/sbom/application.cdx.json')raw.files[name]={value:Buffer.from(v).toString('base64')};
  if(name==='.git-sha')raw.files[name]={value:String(v)};
 });return v;}catch(e){observe(()=>{raw.files[String(p)]={error:e.code??e.name};});throw e;}};
 fs.mkdirSync=function(p,...args){let error;try{return orig.mkdir(p,...args);}catch(e){error=e;throw e;}finally{if(String(p)==='.devsecops')raw.io['output-mkdir']=error?{error:error.code??error.name}:{};}};
 fs.writeFileSync=function(p,data,...args){let error;try{return orig.write(p,data,...args);}catch(e){error=e;throw e;}finally{observe(()=>{
  const name=String(p),key=name==='.devsecops/sbom.json'?'sbom-write':name==='.devsecops/sbom-summary.json'?'summary-write':null;
  if(key){raw.io[key]=error?{error:error.code??error.name}:{};if(!error)reports.push({path:name,bytes:Buffer.byteLength(data),sha256:sha(data)});}
  if(key==='summary-write')raw.now=Date.parse(JSON.parse(String(data)).createdAt);
 });}};
 cp.execFileSync=function(bin,args,options){const startedAtMs=Date.now();try{const v=orig.exec(bin,args,options);observe(()=>{
  if(bin==='unzip')raw.extraction={status:0,base64:Buffer.from(v).toString('base64')};
  events.push({kind:'command',bin:String(bin),argv:[...args],startedAtMs,completedAtMs:Date.now(),exitStatus:0,stdoutSha256:sha(v)});
 });return v;}catch(e){observe(()=>{if(bin==='unzip')raw.extraction={status:e.status??null,error:e.code??e.name};events.push({kind:'command',bin:String(bin),argv:[...args],startedAtMs,completedAtMs:Date.now(),exitStatus:e.status??null,errorClass:e.code??e.name});});throw e;}};
 syncBuiltinESMExports();process.on('exit',exitStatus=>{try{orig.write(3,JSON.stringify({schema:1,sourceId:'sbom',exitStatus,adapterPayload:raw,events,reports})+'\n');}catch{process.exitCode=process.exitCode||74;}});
}
