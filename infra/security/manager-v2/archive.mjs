// No scanner command, network client, Docker API or project executable is loaded.
import fs from 'node:fs';
import {Worker,isMainThread,parentPort,workerData} from 'node:worker_threads';
import {sha,digest,fail,freeze,object} from '../summary-v2/codec.mjs';
import {keys} from './config.mjs';
const activeWorkers=new Set();
export const workerInventory=()=>[...activeWorkers].map(w=>w.threadId);
export const CATALOG=freeze(JSON.parse(fs.readFileSync(new URL('./fixtures/catalog.json',import.meta.url))));
export function decodeArchive(bytes,entry){
 if(!entry||sha(bytes)!==entry.sha256)fail('raw report corruption');
 let raw;try{raw=JSON.parse(bytes.toString());}catch{fail('malformed raw report');}
 if(!object(raw)||!Object.keys(raw).length)fail('missing raw report');
 const fact={component:entry.component,status:'success',raw};
 return {rawReport:raw,rawReportBytesUtf8:bytes.toString(),rawReportDigest:sha(bytes),fact,factDigest:digest(fact),evidenceRefs:[{kind:entry.evidenceClass,source:entry.source,sourceSha256:entry.sourceSha256,archiveSha256:entry.sha256,historicalRuntime:false}],oldDecision:entry.oldDecision};
}
function collect(id,pluginId,approvedDigest){
 const e=CATALOG[id];if(!e||e.pluginId!==pluginId||approvedDigest!==e.sha256)fail('unapproved archive digest/plugin');
 if(!/^[a-z-]+\.json$/.test(e.file))fail('archive path');
 const fd=fs.openSync(new URL('./fixtures/'+e.file,import.meta.url),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.size>2*1024*1024)fail('archive size/type');return decodeArchive(fs.readFileSync(fd),e);}finally{fs.closeSync(fd);}
}
if(!isMainThread){
 try{parentPort.postMessage({ok:true,value:collect(workerData.archiveId,workerData.pluginId,workerData.approvedDigest)});}catch(e){parentPort.postMessage({ok:false,error:e.message.startsWith('POLICY_ERROR:')?e.message:'REPORT_COLLECTION_ERROR'});}
}
export async function executeArchive(plugin,input,{signal}={}){
 keys(input,['archiveId','approvedDigest']);
 const e=CATALOG[input?.archiveId];
 if(!e||e.pluginId!==plugin.pluginId||input.approvedDigest!==e.sha256)fail('unapproved archive digest/plugin');
 if(signal?.aborted)throw Error('RUNNER_CANCELLED');
 const w=new Worker(new URL('./archive.mjs',import.meta.url),{workerData:{archiveId:input.archiveId,pluginId:plugin.pluginId,approvedDigest:input.approvedDigest},env:{},execArgv:[],resourceLimits:{maxOldGenerationSizeMb:64,maxYoungGenerationSizeMb:16}});
 activeWorkers.add(w);
 let timer,abort,packet,exit;
 try{
  packet=await new Promise((resolve,reject)=>{
   timer=setTimeout(()=>reject(Error('RUNNER_TIMEOUT')),plugin.timeout);
   abort=()=>reject(Error('RUNNER_CANCELLED'));signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
   w.once('message',resolve);w.once('error',()=>reject(Error('RUNNER_ERROR')));w.once('exit',code=>{if(code!==0)reject(Error('RUNNER_EXIT_ERROR'));});
  });
  if(!packet.ok)throw Error(packet.error);
 }finally{
  clearTimeout(timer);signal?.removeEventListener('abort',abort);
  exit=await w.terminate();
  if(w.threadId!==-1)throw Error('RUNNER_CLEANUP_FAILED');
  activeWorkers.delete(w);
 }
 return freeze({...packet.value,cleanup:{status:'VERIFIED',workerTerminated:true,threadIdAfterJoin:w.threadId,exitCode:exit},executionScope:'OFFLINE_REPLAY_NOT_RUNTIME'});
}
