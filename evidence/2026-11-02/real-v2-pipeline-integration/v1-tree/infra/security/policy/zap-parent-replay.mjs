// Complete original shared runtime and ZAP Gate replay; external effects are in memory.
import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';import path from 'node:path';import {EventEmitter} from 'node:events';
import {classifyZap} from '../zap-policy.mjs';import {highAlerts} from '../gate-contract.mjs';
const clean=p=>fs.readFileSync(p,'utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
const runtime=clean('infra/security/scanner-runtime.mjs'),gate=clean('infra/security/zap-gate.mjs');
export async function replayZapParent(input){
 const observations=[],reports={},files={},counts={};let classifierInput;
 let manifest;try{manifest=JSON.parse(input.manifest);}catch{manifest={};}
 const tick=key=>key+'#'+(counts[key]=(counts[key]??0)+1);
 function io(key){const occurrence=tick(key),error=input.io[occurrence]??input.io[key];observations.push({type:'io',key,occurrence,ok:!error});if(error)throw Error(error);}
 const fakeFs={readFileSync:p=>{
  io('read:'+p);
  if(Object.hasOwn(reports,p))return reports[p];if(Object.hasOwn(files,p))return files[p];
  if(p==='infra/security/scanner-tools.json')return input.manifest;
  if(p==='infra/security/tools-lock.json')return input.lockText??JSON.stringify({supplyChain:{scanner_manifest_sha256:input.expectedManifestSha256}});
  if(p==='.git-sha')return input.source;
  if(p==='infra/security/zap-confirmations.json')return input.confirmationsText??JSON.stringify(input.confirmations);
  if(Object.hasOwn(input.evidenceFiles,p))return input.evidenceFiles[p];
  if(p.startsWith(manifest.root+'/')){const bytes=input.toolFiles[p.slice(manifest.root.length+1)];if(bytes===undefined)throw Error('Controlled tool file unavailable');return bytes;}
  if(p.endsWith('.class'))return Buffer.from('synthetic compiled class observation');
  throw Error('Uncaptured file read refused: '+p);
 },readlinkSync:p=>{io('readlink:'+p);return input.symlinks[p.slice(manifest.root.length+1)];},mkdirSync:p=>io('mkdir:'+p),mkdtempSync:()=>{io('mkdtemp');return '/tmp/zap-controlled';},copyFileSync:(a,b)=>{io('copy-auth-source');files[b]='synthetic copied source observation';},writeFileSync:(p,v)=>{io('write:'+p);if(p.startsWith('.devsecops/'))reports[p]=String(v);else files[p]=String(v);},rmSync:p=>io('rm:'+p)};
 const spawnSync=(bin,args,options={})=>{
  let key,result={status:0,stdout:'',stderr:''};
  if(bin==='javac')key='javac';
  else if(bin==='kubectl'){
   if(args.includes('lease')){key='lease';result.stdout=JSON.stringify(input.lease);}
   else if(args.includes('create')){key='create';result.stdout=JSON.stringify({metadata:{uid:input.createdUid}});}
   else if(args.includes('wait'))key='pod-ready';
   else if(args.includes('get')&&args.includes('--ignore-not-found')){key='cleanup-verify';result.stdout=input.cleanupRemaining?'pod/zap-controlled':'';}
   else if(args.includes('get')&&args.includes('deploy')){key='deployment';result.stdout=JSON.stringify(input.deployment);}
   else if(args.includes('get')&&args.includes('service')){key='service';result.stdout=JSON.stringify(input.service);}
   else if(args.includes('get')){key='cleanup-pod';result.stdout=JSON.stringify({metadata:{uid:input.currentUid}});}
   else if(args.includes('delete'))key='delete';
   else if(args.includes('exec')){
    const a=args.slice(args.indexOf('--')+1);
    if(a[0]==='timeout'&&a[1]==='2'){key='isolation-probe';const index=counts['isolation-index']??0;counts['isolation-index']=index+1;result.status=input.isolationExits[index]??input.isolationExits.at(-1);}
    else if(a[0]==='timeout'){key='fixture-ready';const index=counts['ready-index']??0;counts['ready-index']=index+1;result.status=input.readinessExits[index]??input.readinessExits.at(-1);}
    else if(a[0]==='java'&&a.includes('-jar')){const label=a.at(-1).split('/').at(-1).replace('.yaml','');key='scan:'+label;}
    else if(a[0]==='java'){key='auth-probe';result.stdout=input.authText??JSON.stringify(input.auth);}
    else if(a[0]==='cat'&&a[1]==='/sys/fs/cgroup/memory.peak'){key='memory-peak';result.stdout='33554432';}
    else if(a[0]==='cat'){
     const file=a[1],label=file.split('/').at(-1).split('.')[0];key='report:'+label+(file.endsWith('.xml')?':xml':'');
     if(file.endsWith('.xml'))result.stdout='<synthetic-zap-report/>';
     else if(Object.hasOwn(input.scanReports,label)){const report=input.scanReports[label];result.stdout=typeof report==='string'?report:JSON.stringify(report);}
     else result={status:1,stdout:'',stderr:'Controlled missing report'};
    }else if(a[0]==='du'){key='du:'+a.at(-1);result.stdout='128 '+a.at(-1);}
    else if(a[0]==='rm')key='session-rm:'+a.at(-1);
    else if(a[0]==='mkdir')key='mkdir-work';
    else if(a[0]==='sh'&&String(a[2]).startsWith('test '))key='security-probe';
    else if(a[0]==='sh'&&String(a[2]).startsWith('kill '))key='fixture-stop';
    else if(a[0]==='sh'&&String(a[2]).startsWith('java '))key='fixture-start';
    else if(a[0]==='sh'&&String(a[2]).includes('.yaml'))key='plan:'+String(a[2]).split('/').at(-1).replace('.yaml','');
    else if(a[0]==='sh')key='class-transfer';
    else throw Error('Uncaptured exec refused: '+JSON.stringify(a));
   }else throw Error('Uncaptured kubectl refused');
  }else throw Error('Uncaptured binary refused: '+bin);
  const occurrence=tick('command:'+key),override=input.commands[occurrence]??input.commands[key];if(override)result={...result,...structuredClone(override)};
  observations.push({type:'command',key,occurrence,bin,args:[...args],timeout:options.timeout,result:structuredClone(result),...(options.input!==undefined?{inputSha256:crypto.createHash('sha256').update(options.input).digest('hex')}:{})});
  return result;
 };
 const spawn=(bin,args)=>{
  const side=bin==='tar'?'source':'sink',e=new EventEmitter(),status=input.transfer[side+'Exit'];e.exitCode=null;e.stdout={pipe:()=>{}};e.stdin=new EventEmitter();
  const close=code=>{if(e.exitCode===null){e.exitCode=code;e.emit('close',code);}};
  e.kill=()=>{observations.push({type:'stream-kill',side});queueMicrotask(()=>close(143));};
  observations.push({type:'stream-process',side,bin,args:[...args],status});
  if(!input.transfer.timeout)queueMicrotask(()=>input.transfer[side+'Error']?e.emit('error',Error('controlled stream spawn error')):close(status));
  return e;
 };
 const net={createServer:()=>{const e=new EventEmitter();e.listen=(_,ip,fn)=>{observations.push({type:'canary',key:'listen',ip,ok:input.canaryListen});input.canaryListen?fn():e.emit('error',Error('controlled listen error'));};e.address=()=>({port:12345});e.close=()=>{observations.push({type:'canary',key:'close'});if(input.canaryCloseError)throw Error('controlled canary close failure');};return e;},connect:()=>{
  const e=new EventEmitter();e.destroy=()=>{};const i=counts['canary-index']??0;counts['canary-index']=i+1;const event=input.canaryEvents[i]??input.canaryEvents.at(-1);observations.push({type:'canary',key:'baseline',event});queueMicrotask(()=>e.emit(event,Error('controlled canary connection error')));return e;
 }};
 class FixedDate extends Date{constructor(...a){super(...(a.length?a:['2026-11-02T00:00:00Z']));}}
 const context={fs:fakeFs,crypto:{...crypto,randomBytes:()=>Buffer.from('abcdef','hex')},net,os:{tmpdir:()=>'/tmp',networkInterfaces:()=>({eth0:[{family:'IPv4',address:input.podIp}]})},path,spawn,spawnSync,Buffer,URL,process:{env:structuredClone(input.env)},Date:FixedDate,Promise,console:{log:()=>{}},setTimeout:(fn,ms)=>{if(ms===150000){observations.push({type:'transfer-timer',timeout:ms,fired:!!input.transfer.timeout});if(input.transfer.timeout)queueMicrotask(fn);}else queueMicrotask(fn);return 1;},clearTimeout:()=>{},highAlerts,classifyZap:(data,ctx,approved)=>{
  if(ctx.targetImage!=='loopback-fixture')classifierInput={report:structuredClone(data),context:structuredClone(ctx),approved:structuredClone(approved)};
  return classifyZap(data,ctx,approved);
 }};
 let exitStatus=0,diagnostic;
 try{const api=vm.runInNewContext('(function(){'+runtime+';return {withScanner,read,run};})()',context);Object.assign(context,api);await vm.runInNewContext('(async()=>{'+gate+'})()',context);}catch(e){exitStatus=1;diagnostic=e.message;}
 return {schema:1,stage:'parent',complete:true,classification:'CONTROLLED_REPLAY',command:'node infra/security/zap-gate.mjs',execution:{exitStatus,...(diagnostic?{diagnostic}:{})},observations,reports,...(classifierInput?{classifierInput}:{})};
}
