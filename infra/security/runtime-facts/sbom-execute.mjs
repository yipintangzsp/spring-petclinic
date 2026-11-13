import fs from 'node:fs';import path from 'node:path';import {spawn} from 'node:child_process';
import {collectRuntimeFacts} from './collector.mjs';import {sha,fail} from '../summary-v2/codec.mjs';
const parent='( nice -n 10 ./mvnw -B package -DskipTests && node infra/security/sbom-verify.mjs )';
async function processCommand(command,{env,cwd,onOutput,observe}){
 const observer=new URL('./observe.mjs',import.meta.url).pathname,startedAtMs=Date.now();
 const p=spawn('/bin/sh',['-c',command],{cwd,env:observe?{...env,RUNTIME_FACT_SOURCE:'sbom',NODE_OPTIONS:[env.NODE_OPTIONS,'--import='+observer].filter(Boolean).join(' ')}:env,stdio:['ignore','pipe','pipe','pipe']});
 let stdout='',stderr='',pipe='',errorClass=null,overflow=false;const limit=24*1024*1024;
 const append=(kind,b)=>{if(Buffer.byteLength(stdout)+Buffer.byteLength(stderr)+Buffer.byteLength(pipe)+b.length>limit){overflow=true;p.kill('SIGTERM');return;}
  if(kind==='pipe')pipe+=b;else{if(kind==='stdout')stdout+=b;else stderr+=b;onOutput(kind,b);}};
 p.stdout.on('data',b=>append('stdout',b));p.stderr.on('data',b=>append('stderr',b));p.stdio[3].on('data',b=>append('pipe',b));p.on('error',e=>{errorClass=e.code??e.name;});
 const r=await new Promise(resolve=>p.once('close',(status,signal)=>resolve({status,signal})));
 if(overflow)fail('SBOM observation overflow; no truncated facts accepted');
 return {...r,errorClass,stdout,stderr,packets:pipe.trim()?pipe.trim().split('\n').map(x=>JSON.parse(x)):[],startedAtMs,completedAtMs:Date.now()};
}
export async function captureSbomParent({sourceId,command,binding,env,cwd,onOutput,buildInput}){
 if(sourceId!=='sbom'||command!==parent)fail('SBOM parent command changed; capture contract must be reviewed');
 // Execute the exact two original commands, preserving original && short-circuit.
 // This orchestration records Maven's actual exit; it never infers success from
 // the presence of a later report, and does not rewrite sbom-verify.mjs.
 const generator=await processCommand('nice -n 10 ./mvnw -B package -DskipTests',{env,cwd,onOutput,observe:false});
 let verifier=null,payload={stage:'production',files:{},io:{},now:Date.now()},reports=[];
 const commandObservation=(stage,r)=>({kind:'ACTUAL_PARENT_OPERATION',stage,startedAtMs:r.startedAtMs,completedAtMs:r.completedAtMs,exitStatus:r.status,signal:r.signal,errorClass:r.errorClass,stdoutSha256:sha(r.stdout),stderrSha256:sha(r.stderr)});
 const evidence=[commandObservation('Maven package',generator)];
 if(generator.status===0&&!generator.signal&&!generator.errorClass){
  verifier=await processCommand('node infra/security/sbom-verify.mjs',{env,cwd,onOutput,observe:true});
  if(verifier.packets.length!==1||verifier.packets[0].sourceId!=='sbom')fail('FACT_CONTRACT_INCOMPLETE: original SBOM verifier observations absent/duplicated');
  const packet=verifier.packets[0];payload=packet.adapterPayload;reports=packet.reports;evidence.push(commandObservation('Original SBOM verifier',verifier),...packet.events);
  if(verifier.status===0&&(!payload.extraction||typeof payload.extraction.base64!=='string'||
    typeof payload.files?.['target/classes/META-INF/sbom/application.cdx.json']?.value!=='string'||
    typeof payload.files?.['.git-sha']?.value!=='string'||
    !['output-mkdir','sbom-write','summary-write'].every(k=>Object.hasOwn(payload.io??{},k))||reports.length!==2))
    fail('FACT_CONTRACT_INCOMPLETE: successful original SBOM verifier lacks native observations');
  const jar=path.join(cwd,'target/spring-petclinic-4.0.0-SNAPSHOT.jar');
  if(fs.existsSync(jar)){const bytes=fs.readFileSync(jar);evidence.push({kind:'LOCAL_GENERATED_JAR_IDENTITY',path:'target/spring-petclinic-4.0.0-SNAPSHOT.jar',bytes:bytes.length,sha256:sha(bytes),imageDigestEnforcementAdded:false});}
 }
 payload.generator={status:generator.status,signal:generator.signal,error:generator.errorClass,stdout:generator.stdout,stderr:generator.stderr};
 if(buildInput)payload.buildInput=structuredClone(buildInput);
 const end=verifier??generator;
 const envelope=collectRuntimeFacts({sourceId,binding,execution:{command,exitStatus:end.status,signal:end.signal,errorClass:end.errorClass},payload,reports,evidence});
 return {envelope,exitStatus:end.status,signal:end.signal,stdout:generator.stdout+(verifier?.stdout??''),stderr:generator.stderr+(verifier?.stderr??'')};
}
