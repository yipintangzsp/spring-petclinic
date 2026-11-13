// Test-only observer: actual calls, unchanged args/stdin/results/errors. Never mock APIs.
import fs from 'node:fs';import cp from 'node:child_process';import crypto from 'node:crypto';import {syncBuiltinESMExports} from 'node:module';import {isDeepStrictEqual} from 'node:util';
import {evaluate} from './work/infra/security/policy/engine.mjs';
const orig={read:fs.readFileSync,write:fs.writeFileSync,spawn:cp.spawnSync};
const config=JSON.parse(orig.read('/fixture/case.json','utf8'));const scope=[['petclinic','petclinic-db'],['petclinic','rabbitmq-client'],['petclinic','petclinic-harbor-pull'],['devsecops-system','kyverno-registry-pull']];
const raw={prerequisites:{credentialPresent:!!process.env.BUSINESS_AGE_FILE},expectedTargetCount:4,readOnly:process.env.DEVSECOPS_READ_ONLY==='true',targets:[]};
const events=[];let current=-1;const readCount=new Map();let errorClass=null;let active=true;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const metadata=x=>({bytes:Buffer.byteLength(x??''),sha256:sha(x??'')});
function pathName(p){return p instanceof URL?p.pathname:String(p);}
fs.readFileSync=function(p,...args){try{const result=orig.read(p,...args);if(active){const name=pathName(p);if(name==='.git-sha')raw.sourceReadSucceeded=true;if(name.endsWith('/20261027/sops'))events.push({kind:'TOOL_SHA_READ',sha256:sha(result)});}return result;}catch(e){if(active){const name=pathName(p);events.push({kind:'FS_READ_ERROR',path:name,errorClass:e.code??e.name});if(name.endsWith('/20261027/sops'))raw.prerequisites.tools=false;if(name==='.git-sha')raw.sourceReadSucceeded=false;}throw e;}};
fs.writeFileSync=function(p,...args){try{const result=orig.write(p,...args);if(active&&pathName(p)==='.devsecops/secrets-gate.json'){raw.reportWriteSucceeded=true;events.push({kind:'REPORT_WRITE',succeeded:true});}return result;}catch(e){if(active&&pathName(p)==='.devsecops/secrets-gate.json'){raw.reportWriteSucceeded=false;events.push({kind:'REPORT_WRITE',succeeded:false,errorClass:e.code??e.name});}throw e;}};
function raceBarrier(){
 if(!['UID_CONTINUITY_FAILURE','VALUE_PRESERVATION_FAILURE'].includes(config.scenario))return;
 orig.write('/fixture/control/request.json',JSON.stringify({operation:config.scenario,namespace:'petclinic',name:'petclinic-db'}));
 const until=Date.now()+45000;
 while(Date.now()<until){if(fs.existsSync('/fixture/control/done.json')){const receipt=JSON.parse(orig.read('/fixture/control/done.json','utf8'));if(!receipt.success)throw Error('MUTATION_MANAGER_FAILED');events.push({kind:'REAL_MUTATION_BARRIER',receipt});return;}Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,50);}
 throw Error('MUTATION_BARRIER_TIMEOUT');
}
cp.spawnSync=function(bin,args,opts){
 const result=orig.spawn(bin,args,opts);if(!active)return result;
 events.push({kind:'PROCESS',command:String(bin),argv:args,exitCode:result.status,signal:result.signal??null,errorClass:result.error?.code??null,timedOut:result.error?.code==='ETIMEDOUT',stdout:metadata(result.stdout),stderr:metadata(result.stderr)});
 if(String(bin).endsWith('/sops')){
  raw.prerequisites.tools=true;current++;raw.targets[current]={expected:{namespace:scope[current][0],name:scope[current][1]},decrypt:{exitStatus:result.status,stdout:result.stdout}};
 }else if(bin==='kubectl'){
  if(args.includes('lease')){raw.prerequisites.manifest=true;if(result.status===0){const x=JSON.parse(result.stdout);raw.prerequisites.lease=x.spec.holderIdentity===process.env.HEAVY_HOLDER;events.push({kind:'LEASE_READ',uid:x.metadata.uid,holderIdentity:x.spec.holderIdentity,holderMatched:raw.prerequisites.lease});}else raw.prerequisites.lease=false;}
  if(args.includes('get')&&args.includes('secret')){
   const name=args[args.indexOf('secret')+1];const count=readCount.get(name)??0;readCount.set(name,count+1);const t=raw.targets[scope.findIndex(x=>x[1]===name)];
   if(count===0){t.readSucceeded=result.status===0;if(result.status===0)t.actual=JSON.parse(result.stdout);}else{t.afterReadSucceeded=result.status===0;if(result.status===0)t.after=JSON.parse(result.stdout);}
  }
  if(args.includes('apply')){const x=JSON.parse(opts.input);const t=raw.targets[scope.findIndex(s=>s[1]===x.metadata.name)];t.applySucceeded=result.status===0;if(x.metadata.name==='petclinic-db'&&result.status===0)raceBarrier();}
  if(args.includes('can-i')){
   const i=args.indexOf('can-i'),verb=args[i+1],res=args[i+2],ns=args[args.indexOf('-n')+1];const verifier=args.some(a=>a.endsWith(':kyverno-admission-controller'));
   let key;if(verifier){key=ns==='devsecops-system'?'ownCredentialGet':verb==='list'?'businessSecretList':res==='secret/petclinic-db'?'businessDatabaseGet':'oldCrossGet';}else{key=ns==='data-infra'?'otherNamespace':ns==='devsecops-system'?(verb==='list'?'registryList':verb==='create'?'registryCreate':res==='secret/kyverno-registry-pull'?'knownRegistryGet':'registryForeignGet'):(verb==='list'?'listSecrets':verb==='create'?'createSecret':res==='secret/petclinic-db'?'knownGet':'foreignGet');}
   const map=verifier?'verifierRbac':'rbac';raw[map]??={};raw[map][key]=String(result.stdout).trim();
  }
 }
 return result;
};
syncBuiltinESMExports();
process.on('uncaughtExceptionMonitor',e=>{errorClass=e.code??e.name;events.push({kind:'UNCAUGHT_EXCEPTION',errorClass,messageSha256:sha(e.message)});});
function safeObject(obj){if(!obj)return null;return {kind:obj.kind,metadata:{name:obj.metadata?.name,namespace:obj.metadata?.namespace,uid:obj.metadata?.uid},type:obj.type,keyNames:Object.keys(obj.data??{}).sort(),dataSha256:sha(JSON.stringify(Object.fromEntries(Object.entries(obj.data??{}).sort())))};}
process.on('exit',code=>{
 active=false;syncBuiltinESMExports();
 const before=JSON.stringify(raw);let policy,adapterError=null;
 try{policy=evaluate({component:'sops',status:'success',raw},{policyVersion:'baseline-v1',securityLevel:'standard'});}catch(e){adapterError=e.message;}
 const unchanged=before===JSON.stringify(raw);const oldDecision=code===0?'PASS':'FAIL';
 const safe={prerequisites:raw.prerequisites,sourceReadSucceeded:raw.sourceReadSucceeded,readOnly:raw.readOnly,expectedTargetCount:raw.expectedTargetCount,targets:raw.targets.map(t=>({expected:t.expected,decrypt:{exitStatus:t.decrypt.exitStatus,stdout:metadata(t.decrypt.stdout)},readSucceeded:t.readSucceeded,actual:safeObject(t.actual),applySucceeded:t.applySucceeded,afterReadSucceeded:t.afterReadSucceeded,after:safeObject(t.after),uidEqual:t.actual&&t.after?t.actual.metadata.uid===t.after.metadata.uid:null,dataEqual:t.actual&&t.after?isDeepStrictEqual(t.actual.data,t.after.data):null})),rbac:raw.rbac,verifierRbac:raw.verifierRbac,reportWriteSucceeded:raw.reportWriteSucceeded};
 const envelope={scenario:config.scenario,classification:'REAL_CONTROLLED_EXECUTION',rawEvidence:{facts:safe,events,rawInputSha256:sha(before),rawPreserved:unchanged,redaction:'Synthetic decrypted stdout/data stay in memory only; original fingerprints+equality retained, no raw values archived'},oldGate:{exitCode:code,signal:null,errorClass,oldDecision},adapterRawOutput:policy?.sopsFacts??null,policy:policy??null,adapterError,comparison:policy?.decision===oldDecision?'MATCH':policy?.decision?'DRIFT':'INCOMPLETE'};
 orig.write('/fixture/results/result.json',JSON.stringify(envelope,null,2));
});
