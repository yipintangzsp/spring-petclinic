// Passive --import observer. Same argv/stdin/return values/errors and wall clock.
// Raw sensitive values exist only in memory and the inherited private pipe fd3.
// No Policy, no filesystem report of raw facts, no fault injection.
import fs from 'node:fs';
import cp from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
import './kyverno-observer.mjs';
import './kubescape-observer.mjs';
import './sbom-observer.mjs';
import './parent-observer.mjs';

const id=process.env.RUNTIME_FACT_SOURCE;
if(id&&['sops','falco-baseline','falco-final'].includes(id)){
  const original={read:fs.readFileSync,write:fs.writeFileSync,mkdir:fs.mkdirSync,spawn:cp.spawnSync,fetch:globalThis.fetch,now:Date.now};
  const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
  const text=b=>b==null?'':Buffer.isBuffer(b)?b.toString():String(b);
  const filename=p=>p instanceof URL?p.pathname:String(p);
  const events=[],readFiles=new Map();let stopped=false,errorClass=null,sourceRead=false,baselineClockCaptured=false,toolManifest,toolLock;
  const raw=id==='sops'?{prerequisites:{credentialPresent:!!process.env.BUSINESS_AGE_FILE},readOnly:process.env.DEVSECOPS_READ_ONLY==='true',expectedTargetCount:4,targets:[]}:
    {mode:id==='falco-baseline'?'baseline':'check',now:original.now(),build:String(process.env.BUILD_NUMBER),configuration:{},observations:{files:{},samples:[],baselineExists:false}};
  const scope=[['petclinic','petclinic-db'],['petclinic','rabbitmq-client'],['petclinic','petclinic-harbor-pull'],['devsecops-system','kyverno-registry-pull']];
  let decrypt=-1,workload=0,reads=new Map();
  const falco=()=>raw.observations;
  const event=(kind,value)=>events.push({kind,...value});
  function fileObservation(name,result,error){
    if(name.endsWith('scanner-tools.json')&&!error){toolManifest=JSON.parse(text(result));readFiles.set(name,hash(result));}
    if(name.endsWith('tools-lock.json')&&!error){try{toolLock=JSON.parse(text(result));}catch{}}
    if(id==='sops'){
      if(name==='.git-sha'){raw.sourceReadSucceeded=!error;if(!error)raw.prerequisites.tools=true;}
      if(toolManifest){const e=toolManifest.files.find(x=>name===toolManifest.root+'/'+x.path);if(e&&!e.symlink){raw.prerequisites.tools=raw.prerequisites.tools!==false&&!error&&hash(result)===e.sha256;}}
      if(toolManifest&&toolLock?.supplyChain)raw.prerequisites.manifest=readFiles.get('infra/security/scanner-tools.json')===toolLock.supplyChain.scanner_manifest_sha256;
      return;
    }
    const keys=[['isolated-sensor-proof.json','proof'],['runtime/lock.json','lock'],['.git-sha','source'],['runtime-baseline.json','baseline']];
    for(const [suffix,key] of keys)if(name.endsWith(suffix)){
      falco().files[key]=error?{error:error.code??error.name}:{value:text(result)};
      if(key==='source'&&!error)sourceRead=true;
      if(key==='baseline'&&!error)falco().baselineExists=true;
    }
    if(name.endsWith('runtime/falco.json'))falco().files.manifestHash=error?{error:error.code??error.name}:{value:hash(result)};
  }
  fs.readFileSync=function(p,...args){try{const value=original.read(p,...args);fileObservation(filename(p),value);return value;}catch(e){fileObservation(filename(p),null,e);throw e;}};
  fs.mkdirSync=function(p,...args){try{const value=original.mkdir(p,...args);if(id.startsWith('falco')&&filename(p)==='.devsecops')falco().mkdirSucceeded=true;return value;}catch(e){if(id.startsWith('falco')&&filename(p)==='.devsecops')falco().mkdirSucceeded=false;throw e;}};
  fs.writeFileSync=function(p,...args){let success=false;try{const value=original.write(p,...args);success=true;return value;}finally{
    const n=filename(p);
    if(id==='sops'&&n==='.devsecops/secrets-gate.json')raw.reportWriteSucceeded=success;
    if(id.startsWith('falco')){if(n==='.devsecops/runtime-health.json')falco().reportWriteSucceeded=success;if(n==='.devsecops/runtime-baseline.json')falco().baselineWriteSucceeded=success;}
  }};
  // The first original Date.now after source read is the baseline stability
  // check. Later query clocks must not replace this prerequisite clock.
  Date.now=function(){const value=original.now();if(sourceRead&&id==='falco-baseline'&&!baselineClockCaptured){raw.now=value;baselineClockCaptured=true;}return value;};
  cp.spawnSync=function(bin,args,options){
    const started=original.now();const result=original.spawn(bin,args,options);const completed=original.now();
    // Observation copies do not change the caller's result or options.
    const r={status:result.status,stdout:text(result.stdout),stderr:text(result.stderr),error:result.error?{code:result.error.code??result.error.name}:null};
    event('command',{bin:String(bin),argv:[...args],startedAtMs:started,completedAtMs:completed,exitStatus:r.status,errorClass:r.error?.code??null,stdoutSha256:hash(r.stdout),stderrSha256:hash(r.stderr)});
    if(bin==='kubectl'&&args.includes('lease')){
      let owned=false;try{owned=r.status===0&&JSON.parse(r.stdout).spec.holderIdentity===(process.env.HEAVY_HOLDER||'jenkins-petclinic-'+process.env.BUILD_NUMBER);}catch{}
      if(id==='sops')raw.prerequisites.lease=owned;else falco().leaseOwned=owned;
    }
    if(id==='sops'){
      if(String(bin).endsWith('/sops')){decrypt++;raw.targets[decrypt]={expected:{namespace:scope[decrypt]?.[0],name:scope[decrypt]?.[1]},decrypt:{exitStatus:r.status,stdout:r.stdout}};}
      if(bin==='kubectl'&&args.includes('get')&&args.includes('secret')){
        const name=args[args.indexOf('secret')+1],i=scope.findIndex(x=>x[1]===name),count=reads.get(name)??0;reads.set(name,count+1);const t=raw.targets[i];
        if(t){const after=count>0;t[after?'afterReadSucceeded':'readSucceeded']=r.status===0;if(r.status===0)t[after?'after':'actual']=JSON.parse(r.stdout);}
      }
      if(bin==='kubectl'&&args.includes('apply')){const v=JSON.parse(text(options?.input));const t=raw.targets[scope.findIndex(x=>x[1]===v.metadata?.name)];if(t)t.applySucceeded=r.status===0;}
      if(bin==='kubectl'&&args.includes('can-i')){
        const i=args.indexOf('can-i'),verb=args[i+1],res=args[i+2],ns=args[args.indexOf('-n')+1],verifier=args.some(x=>x.endsWith(':kyverno-admission-controller'));
        const key=verifier?(ns==='devsecops-system'?'ownCredentialGet':verb==='list'?'businessSecretList':res==='secret/petclinic-db'?'businessDatabaseGet':'oldCrossGet'):
          ns==='data-infra'?'otherNamespace':ns==='devsecops-system'?(verb==='list'?'registryList':verb==='create'?'registryCreate':res==='secret/kyverno-registry-pull'?'knownRegistryGet':'registryForeignGet'):
          verb==='list'?'listSecrets':verb==='create'?'createSecret':res==='secret/petclinic-db'?'knownGet':'foreignGet';
        const map=verifier?'verifierRbac':'rbac';raw[map]??={};raw[map][key]=r.stdout.trim();
      }
    }else if(bin==='kubectl'){
      if(args.includes('ds'))falco().ds=r;
      else if(args.includes('node'))falco().node=r;
      else if(args.includes('logs')){
        if(args.includes('--tail=500'))falco().diagnosticLog=r;
        else{
          const since=args.find(x=>x.startsWith('--since-time='))?.slice('--since-time='.length);
          // Exact end derives from THIS command's captured lower query bound,
          // not a wait, previous sample, duration estimate or fixed +16 seconds.
          const end=Date.parse(since)+15000;
          falco().samples.push({windowEndMs:end,log:r,startedAtMs:started,logCompletedAtMs:completed,querySince:since});
        }
      }else if(args.includes('petclinic')&&args.includes('pods')){
        const sample=falco().samples[workload++];if(sample){sample.workloads=r;sample.completedAtMs=completed;}
      }else if(args.includes('pods'))falco().sensorPods=r;
    }
    return result;
  };
  if(id.startsWith('falco'))globalThis.fetch=async function(...args){try{const r=await original.fetch(...args);falco().health={ok:r.ok,status:r.status};return r;}catch(e){falco().health={ok:false,error:e.code??e.name};throw e;}};
  syncBuiltinESMExports();
  process.on('uncaughtExceptionMonitor',e=>{errorClass=e.code??e.name;});
  process.on('exit',code=>{
    if(stopped)return;stopped=true;
    const packet={schema:1,sourceId:id,pid:process.pid,exitStatus:code,errorClass,adapterPayload:raw,events};
    // Inherited pipe is never a path or archive. Parent consumes once in memory.
    try{original.write(3,JSON.stringify(packet)+'\n');}catch{process.exitCode=process.exitCode||74;}
  });
}
