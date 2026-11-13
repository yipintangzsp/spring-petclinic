// Passive facts from the two ORIGINAL Kyverno commands. No policy evaluation,
// admission simulation, extra Kubernetes call, changed result or injected fault.
import fs from 'node:fs';
import cp from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
if(process.env.RUNTIME_FACT_SOURCE==='kyverno'){
  const original={read:fs.readFileSync,write:fs.writeFileSync,spawn:cp.spawnSync};
  const phase=process.argv[1]?.endsWith('/rbac-contract.mjs')?'rbac':process.argv[1]?.endsWith('/admission-gate.mjs')?'admission':null;
  if(phase){
    const configuration={},observations={rbac:[],probes:[],owners:[]},events=[];
    const hash=v=>crypto.createHash('sha256').update(v??'').digest('hex');
    const str=v=>v==null?'':String(v);
    const observe=fn=>{try{fn();}catch(e){events.push({kind:'OBSERVER_ERROR',errorClass:e.name});}};
    fs.readFileSync=function(p,...args){
      try{const value=original.read(p,...args);observe(()=>{
        const n=String(p);
        for(const [suffix,key] of [['/tools-lock.json','tools'],['production-baseline.json','baseline'],['production-exceptions.json','exceptions']])
          if(n.endsWith(suffix))configuration[key]=JSON.parse(str(value));
        if(n==='.git-sha')observations.sourceReadSucceeded=true;
      });return value;}catch(e){if(String(p)==='.git-sha')observations.sourceReadSucceeded=false;throw e;}
    };
    fs.writeFileSync=function(p,...args){let success=false;try{const value=original.write(p,...args);success=true;return value;}finally{
      const n=String(p);if(n==='.devsecops/kyverno-rbac.json')observations.rbacReportWriteSucceeded=success;
      if(n==='.devsecops/admission-gate.json')observations.admissionReportWriteSucceeded=success;
    }};
    cp.spawnSync=function(bin,args,options){
      const startedAtMs=Date.now(),r=original.spawn(bin,args,options),completedAtMs=Date.now();
      observe(()=>{
        const value={status:r.status,stdout:str(r.stdout),stderr:str(r.stderr),error:r.error?{code:r.error.code??r.error.name}:null};
        events.push({kind:'command',bin:String(bin),argv:[...args],startedAtMs,completedAtMs,exitStatus:r.status,
          stdoutSha256:hash(value.stdout),stderrSha256:hash(value.stderr),errorClass:value.error?.code??null});
        if(bin!=='kubectl')return;
        if(phase==='rbac')observations.rbac.push(value);
        else if(args.includes('--dry-run=server'))observations.probes.push(value);
        else if(args.includes('clusterpolicy'))observations.policy=value;
        else if(args.includes('deploy,ds,sts'))observations.workloads=value;
        else if(args.includes('pods'))observations.owners.push(value);
      });return r;
    };
    syncBuiltinESMExports();
    process.on('exit',exitStatus=>{
      try{original.write(3,JSON.stringify({schema:1,sourceId:'kyverno',phase,exitStatus,configuration,observations,events})+'\n');}
      catch{process.exitCode=process.exitCode||74;}
    });
  }
}

export function mergeKyvernoPackets(packets){
  if(!packets.length||packets.length>2||packets.some(p=>p.sourceId!=='kyverno'||!['rbac','admission'].includes(p.phase)))throw Error('Kyverno command observations absent or malformed');
  if(new Set(packets.map(p=>p.phase)).size!==packets.length||packets[0].phase!=='rbac')throw Error('Duplicate or reordered Kyverno observation');
  if(packets[0].exitStatus===0&&packets[1]?.phase!=='admission')throw Error('Successful RBAC missing admission execution');
  if(packets[0].exitStatus!==0&&packets.length!==1)throw Error('Admission executed after RBAC failure');
  const configuration=Object.assign({},...packets.map(p=>p.configuration));
  const observations=Object.assign({},...packets.map(p=>p.observations));
  observations.rbac=packets[0].observations.rbac;
  observations.sourceReadSucceeded=packets[0].observations.sourceReadSucceeded===true;
  observations.rbacReportWriteSucceeded=packets[0].observations.rbacReportWriteSucceeded===true;
  observations.configurationReadSucceeded=['tools','baseline','exceptions'].every(k=>Object.hasOwn(configuration,k));
  return {adapterPayload:{configuration,observations},events:packets.flatMap(p=>p.events)};
}
