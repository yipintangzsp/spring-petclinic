// Test-only collector: execute the WHOLE unchanged production source with inert I/O.
// Never imported by the Policy adapter; no real subprocess/socket/cluster is used.
import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';import {EventEmitter} from 'node:events';
const source=fs.readFileSync('infra/security/source-gate.mjs','utf8').replace(/^import .*;\s*$/gm,'');
const command='node infra/security/source-gate.mjs';
const response=(stdout='',status=0,stderr='')=>({status,stdout,stderr});
export async function replayGitleaksParent(input){
 const observations=[],reports={},counts={},sourceLines=[];let scanPath,podGets=0,reviewed,reviewRead=false;
 const occurrence=key=>key+'#'+(counts[key]=(counts[key]??0)+1);
 function failure(key){const tag=occurrence(key),error=input.io[tag]??input.io[key];observations.push({type:'io',key,occurrence:tag,ok:!error});if(error)throw Error(error);}
 const fakeFs={mkdirSync:p=>failure('mkdir:'+p),readFileSync:p=>{
  failure('read:'+p);
  if(p==='infra/security/tools-lock.json')return input.toolLock;
  if(p==='infra/security/reviewed-false-positives.json'){reviewRead=true;reviewed=structuredClone(input.reviewedEntries);return input.reviewText??JSON.stringify({entries:reviewed});}
  throw Error('Uncaptured file access refused: '+p);
 },writeFileSync:(p,v)=>{failure('write:'+p);reports[p]=String(v);}};
 const spawnSync=(bin,args,opts)=>{
  let key,result;
  if(bin==='git'){key=args[0]==='rev-parse'?'git-revision':'source-archive';result=response(key==='git-revision'?input.source:Buffer.from('disposable-source-archive'));if(key==='source-archive'&&input.archiveOversize)result.stdout={length:128*1024*1024+1};}
  else if(bin==='kubectl'){
   if(args.includes('lease')){key='lease';result=response(JSON.stringify(input.lease));}
   else if(args.includes('create')){key='create';result=response(JSON.stringify({metadata:{uid:input.createdUid}}));}
   else if(args.includes('wait')){key='ready';result=response();}
   else if(args.includes('get')&&args.includes('--ignore-not-found')){key='cleanup-verify';result=response(input.cleanupRemaining?'pod/source-fixture':'');}
   else if(args.includes('get')){key='pod-get-'+(++podGets);result=response(JSON.stringify({metadata:{uid:input.podUids[podGets-1]??input.createdUid},status:{containerStatuses:[{imageID:input.imageId}]},spec:{containers:[{resources:input.resources}]}}));}
   else if(args.includes('delete')){key='delete';result=response();}
   else if(args.includes('exec')){
    const a=args.slice(args.indexOf('--')+1);
    if(a[0]==='gitleaks'){scanPath=a[2];key='scan:'+scanPath;const s=input.scans[scanPath];result=response(s.stdout??'',s.exit,s.stderr??'');if(s.error)result.error=structuredClone(s.error);}
    else if(a[0]==='cat'&&['/work/positive.json','/work/clean.json','/work/source.json'].includes(a[1])){key='report:'+a[1];result=Object.hasOwn(input.reportFiles,a[1])?response(input.reportFiles[a[1]]):response('',1,'controlled missing report');}
    else if(a[0]==='cat'&&a[1].startsWith('/work/source/')){
     key='source-line:'+a[1];const text=input.sourceText[a[1]];result=text===undefined?response('',1,'source unavailable'):response(text);
     if(text!==undefined)text.split(/\r?\n/).forEach((line,i)=>sourceLines.push({path:a[1].slice('/work/source/'.length),line:i+1,sha256:crypto.createHash('sha256').update(line).digest('hex')}));
    }else if(a[0]==='cat'){key='memory-peak';result=response(input.memoryPeak);}
    else if(a[0]==='nc'&&a[1]==='--help'){key='probe-help';result=response(input.ncHelp);}
    else if(a[0]==='nc'&&a.includes('-v')){key='isolation-probe';const index=counts['probe-index']??0;counts['probe-index']=index+1;result=response('',input.isolationExits[index]??input.isolationExits.at(-1));}
    else if(a[0]==='nc'){key='node-network';result=response('',input.nodeNetworkExit);}
    else if(a[0]==='id'){key='effective-uid';result=response(input.effectiveUid);}
    else if(a[0]==='touch'){key='readonly-probe';result=response('',input.readOnlyExit,input.readOnlyStderr);}
    else if(a[0]==='sh'&&String(a[2]).startsWith('test ')){key='token-probe';result=response();}
    else if(a[0]==='sh'){key='fixture-write';result=response();}
    else if(a[0]==='mkdir'){key='work-mkdir';result=response();}
    else if(a[0]==='tar'){key='archive-transfer';result=response();}
    else throw Error('Uncaptured exec refused: '+JSON.stringify(a));
   }else throw Error('Uncaptured kubectl refused');
  }else throw Error('Uncaptured subprocess refused: '+bin);
  const tag=occurrence('command:'+key),override=input.commands[tag]??input.commands[key];if(override)result={...result,...structuredClone(override)};
  observations.push({type:'command',key,bin,args:[...args],timeout:opts?.timeout,encoding:opts?.encoding,result:structuredClone(result),...(opts?.input!==undefined?{inputSha256:crypto.createHash('sha256').update(typeof opts.input==='string'||Buffer.isBuffer(opts.input)?opts.input:JSON.stringify(opts.input)).digest('hex')}:{})});
  return result;
 };
 const net={createServer:()=>{const e=new EventEmitter();e.listen=(_,ip,callback)=>{observations.push({type:'canary',key:'listen',ip,ok:input.canaryListen});if(input.canaryListen)callback();else e.emit('error',Error('controlled canary listen error'));};e.address=()=>({port:12345});e.close=()=>{observations.push({type:'canary',key:'close'});if(input.canaryCloseError)throw Error('controlled canary close error');};return e;},connect:()=>{
  const e=new EventEmitter();e.destroy=()=>{};const index=counts['canary-connect']??0;counts['canary-connect']=index+1;const event=input.canaryEvents[index]??input.canaryEvents.at(-1);observations.push({type:'canary',key:'baseline',event});queueMicrotask(()=>e.emit(event,Error('controlled canary connection error')));return e;
 }};
 class FixedDate extends Date{constructor(...args){super(...(args.length?args:['2026-11-01T00:00:00Z']));}}
 const context={fs:fakeFs,crypto:{...crypto,randomBytes:()=>Buffer.from('abcdef','hex')},net,os:{networkInterfaces:()=>input.interfaces},syntheticCredential:()=>{observations.push({type:'fixture',key:'syntheticCredential',classification:'NON_PRODUCTION_SYNTHETIC'});return 'non-secret-disposable-test-marker';},spawnSync,Buffer,process:{env:structuredClone(input.env)},Date:FixedDate,console:{log:()=>{}},setTimeout:fn=>{queueMicrotask(fn);return 1;},Promise};
 let exitStatus=0,diagnostic;
 try{await vm.runInNewContext('(async()=>{'+source+'})()',context);}catch(e){exitStatus=1;diagnostic=e.message;}
 const classifierInput=reviewRead?{sourcePrefix:'/work/source/',findings:[],reviewedEntries:reviewed,sourceLines}:null;
 if(classifierInput){try{classifierInput.findings=JSON.parse(reports['.devsecops/source-gate.json']).sourceScan?.findings??[];}catch{}}
 return {schema:1,stage:'parent',complete:true,classification:'CONTROLLED_REPLAY',command,execution:{exitStatus,...(diagnostic?{diagnostic}:{})},observations,reports,classifierInput};
}
