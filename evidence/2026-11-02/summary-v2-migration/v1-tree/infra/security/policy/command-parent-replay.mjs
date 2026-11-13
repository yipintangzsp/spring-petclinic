// Whole unchanged Gate collector for frozen compatibility tests only; Policy never imports it.
import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';import {EventEmitter} from 'node:events';
import {classifySemgrep,enforcedRules} from '../semgrep-policy.mjs';
const clean=p=>fs.readFileSync(p,'utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ',''),runtime=clean('infra/security/scanner-runtime.mjs'),audit=clean('infra/security/command-audit.mjs'),semgrep=clean('infra/security/semgrep-gate.mjs').replace("await import('node:child_process')","await Promise.resolve(childProcess)");
const read=p=>JSON.parse(fs.readFileSync(p)),command=read('resources/security-manager/petclinic-adapter.json').find(x=>x.id==='semgrep').command;
const response=(stdout='',status=0,stderr='')=>({status,stdout:typeof stdout==='string'?stdout:JSON.stringify(stdout),stderr});
export async function replayCommandParent(raw){
 const operations=[];
 async function operation(stage){
  const r=stage==='command-audit'?raw.audit:raw.semgrep,reports={},observations=[];let scanIndex=0,scanResult,findIndex=0;
  const io=key=>{observations.push({type:'io',key});if(raw.io[key])throw Error(raw.io[key]);};
  const fsFake={readFileSync:(p,encoding)=>{
   observations.push({type:'file-read',path:p});if(raw.fileErrors[p])throw Error(raw.fileErrors[p]);
   if(p==='infra/security/scanner-tools.json')return raw.runtime.manifest;
   if(p==='infra/security/tools-lock.json')return JSON.stringify({supplyChain:{scanner_manifest_sha256:raw.runtime.expectedManifestSha256}});
   const tools=JSON.parse(raw.runtime.manifest);if(p.startsWith(tools.root+'/')){const x=raw.runtime.tools[p.slice(tools.root.length+1)];if(!x||x.error)throw Error('Tool unavailable');return {observedHash:x.sha256};}
   if(p==='.git-sha')return raw.source;
   if(raw.audit.sourceFiles.includes(p))return raw.audit.sourceText;
   return fs.readFileSync(p,encoding);
  },readlinkSync:p=>raw.runtime.tools[p.slice(JSON.parse(raw.runtime.manifest).root.length+1)]?.symlink,mkdirSync:p=>io('mkdir:'+p),writeFileSync:(p,v)=>{io('write:'+p);reports[p]=String(v);}};
  const runCommand=(bin,args,input)=>{
   let result;
   if(bin==='git')result=response(raw.audit.sourceFiles.join('\n'),raw.audit.gitFailure?1:0,'git listing failed');
   else if(args.includes('lease'))result=response({spec:{holderIdentity:raw.runtime.leaseOwned?'fixture-holder':'foreign'}});
   else if(args.includes('create'))result=r.create?response({metadata:{uid:r.uid}}):response('',1,'create failed');
   else if(args.includes('wait'))result=args.includes('--for=delete')?(r.deleteWait===false?response('',1,'delete wait failed'):response()):(r.ready?response():response('',1,'readiness timeout'));
   else if(args.includes('get'))result=args.includes('--ignore-not-found')?response(r.cleanup?'':'pod/still-present'):response({metadata:{uid:r.currentUid}});
   else if(args.includes('delete'))result=r.delete?response():response('',1,'delete failed');
   else if(args.includes('exec')){
    const a=args.slice(args.indexOf('--')+1);
    if(stage==='command-audit')result=raw.python;
    else if(a[0]==='timeout')result=response('',raw.runtime.isolationDenied?124:0);
    else if(a[0]==='sh'&&String(a[2]).startsWith('test '))result=r.securityProbe?response():response('',1,'security probe failed');
    else if(a[0]==='cat')result=r.memoryPeakFailure?response('',2,'memory peak read failed'):response('33554432');
    else if(a[0]==='find'){
     const names=['positive','negative','repeat','commandPositive','commandNegative','commandRepeat','sourceReport'];scanResult=r[names[findIndex++]];
     if(!r.find)result=response('',1,'find failed');else if(r.unexpectedPath)result=response('/foreign/Injected.java');else result=response(Array.from({length:r.filesPerScan},(_,i)=>a[1]+'/File'+i+'.java').join('\n'));
    }else if(a[0]==='/work/tools/semgrep/semgrep-core')result=scanResult?.executionError?{status:null,error:'timeout',stdout:'',stderr:'timeout'}:response(scanResult?.rawText??JSON.stringify(scanResult));
    else if(a[0]==='sh'&&a[1]==='-c'&&!r.fixtureWrites)result=response('',1,'fixture transfer failed');
    else result=response();
   }else result=response('',1,'unexpected external call');
   observations.push({type:'command',bin,args:[...args],result:structuredClone(result),...(input!==undefined?{input:Buffer.isBuffer(input)?input.toString():input}:{})});return result;
  };
  const spawnSync=(bin,args,opts)=>runCommand(bin,args,opts?.input);
  const spawn=(bin,args)=>{
   const e=new EventEmitter();e.stdout={pipe:()=>{}};e.stdin=new EventEmitter();e.exitCode=null;e.kill=()=>{};
   const status=bin==='git'?(r.sourceArchive?0:1):bin==='tar'?(r.toolTransfer?0:1):args.includes('--request-timeout=120s')?(r.sourceTransfer?0:1):(r.toolTransfer?0:1);
   observations.push({type:'stream-process',bin,args:[...args],status});queueMicrotask(()=>{e.exitCode=status;e.emit('close',status);});return e;
  };
  const net={createServer:()=>{const e=new EventEmitter();e.listen=(_,ip,cb)=>{observations.push({type:'canary-listen',ok:raw.runtime.canaryListen});if(raw.runtime.canaryListen)cb();else e.emit('error',Error('canary listen failed'));};e.address=()=>({port:12345});e.close=()=>observations.push({type:'canary-close'});return e;},connect:()=>{const e=new EventEmitter();e.destroy=()=>{};queueMicrotask(()=>e.emit(raw.runtime.canaryWorks?'connect':'error',Error('canary baseline failed')));return e;}};
  const cryptoFake={randomBytes:()=>Buffer.from('abcdef'),createHash:a=>({update:v=>({digest:e=>v?.observedHash??crypto.createHash(a).update(v).digest(e)})})};
  const context={fs:fsFake,crypto:cryptoFake,net,os:{networkInterfaces:()=>({eth0:[{family:'IPv4',address:raw.runtime.podIP}]})},spawnSync,spawn,childProcess:{spawn},Buffer,process:{env:{BUILD_NUMBER:raw.build,HEAVY_HOLDER:'fixture-holder',GATE_SEMGREP:raw.mode}},console:{log:()=>{}},classifySemgrep,enforcedRules,Promise,setTimeout:(fn,ms)=>{if(ms<60000)queueMicrotask(fn);return 1;},clearTimeout:()=>{}};
  let exitStatus=0,diagnostic;
  try{const h=vm.runInNewContext('(function(){'+runtime+';return {run,kube,read,requireLease,verifyTools,toolchain,withScanner,transfer};})()',context);Object.assign(context,h);await vm.runInNewContext('(async()=>{'+(stage==='command-audit'?audit:semgrep)+'})()',context);}catch(error){exitStatus=1;diagnostic=error.message;}
  return {stage,execution:{exitStatus,...(diagnostic?{diagnostic}:{})},reports,observations};
 }
 const first=await operation('command-audit');operations.push(first);if(first.execution.exitStatus===0)operations.push(await operation('semgrep'));
 return {schema:1,stage:'parent',complete:true,classification:'CONTROLLED_REPLAY',command,operations};
}
