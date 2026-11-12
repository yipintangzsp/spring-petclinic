// One bounded delivery through the already-authorized, fixed Loki SSH channel.
// No scanner, Policy evaluation, configurable URL, shell, credential or admin API.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {routeResultsWithLoki} from '../router.mjs';
import {createLokiTransport,validateLokiEvent} from '../consumers/loki.mjs';
import {digest} from '../../summary-v2/codec.mjs';
const port=32189,known=path.join(os.homedir(),'.ssh/known_hosts');
const fault=code=>Object.assign(Error(code),{code});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const requireValue=(value,code)=>{if(!value)throw fault(code);};
function save(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o400});}
function get(route){return new Promise((resolve,reject)=>{
 const req=http.get({hostname:'127.0.0.1',port,path:route,agent:false,maxHeaderSize:8192},res=>{
  let size=0;const chunks=[];res.on('data',b=>{size+=b.length;if(size>65536){req.destroy(fault('LOKI_QUERY_OUTPUT_LIMIT'));return;}chunks.push(b);});
  res.on('error',()=>reject(fault('LOKI_QUERY_RESPONSE_LOST')));
  res.on('end',()=>{if(res.statusCode!==200)return reject(fault('LOKI_QUERY_HTTP_REJECTED'));try{resolve(JSON.parse(Buffer.concat(chunks)));}catch{reject(fault('LOKI_QUERY_RESPONSE_INVALID'));}});
 });req.setTimeout(2500,()=>req.destroy(fault('LOKI_QUERY_TIMEOUT')));req.on('error',e=>reject(fault(e.code==='ECONNREFUSED'?'LOKI_CHANNEL_NOT_READY':/^[A-Z_]+$/.test(e.code??'')?e.code:'LOKI_QUERY_CONNECTION_FAILED')));
});}
export async function withExistingLokiChannel(action){
 const st=fs.lstatSync(known);requireValue(st.isFile()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&!(st.mode&0o022),'LOKI_KNOWN_HOSTS_UNSAFE');
 await new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',()=>reject(fault('LOKI_CHANNEL_PORT_OCCUPIED')));s.listen(port,'127.0.0.1',()=>s.close(resolve));});
 const child=spawn('/usr/bin/ssh',['-F','/dev/null','-T','-N','-n',
  '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','PreferredAuthentications=publickey',
  '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes',
  '-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+known,'-o','GlobalKnownHostsFile=/dev/null',
  '-o','HostKeyAlias=192.168.1.58','-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
  '-o','ServerAliveInterval=4','-o','ServerAliveCountMax=2','-o','ControlMaster=no','-o','ControlPersist=no',
  '-o','ForwardAgent=no','-o','ForwardX11=no','-L','127.0.0.1:32189:10.43.7.197:3100','zhang@192.168.64.11'],
  {stdio:['ignore','ignore','ignore'],env:{PATH:'/usr/bin:/bin',LANG:'C'}});
 let spawnError=false;child.on('error',()=>{spawnError=true;});
 const exited=new Promise(resolve=>child.once('close',resolve)),shutdown=()=>{if(child.exitCode===null)child.kill('SIGTERM');};process.once('exit',shutdown);
 try{
  let ready=false;
  for(let n=0;n<30;n++){
   requireValue(!spawnError&&child.exitCode===null,'LOKI_SSH_CHANNEL_FAILED');
   try{const b=await get('/loki/api/v1/status/buildinfo');if(b.version==='3.7.4'){ready=true;break;}}catch(e){if(e.code!=='LOKI_CHANNEL_NOT_READY')throw e;}
   await pause(200);
  }
  requireValue(ready&&child.exitCode===null,'LOKI_TARGET_IDENTITY_NOT_VERIFIED');
  return await action();
 }finally{
  shutdown();let closed=await Promise.race([exited.then(()=>true),pause(1500).then(()=>false)]);
  if(!closed){child.kill('SIGKILL');closed=await Promise.race([exited.then(()=>true),pause(1000).then(()=>false)]);}
  process.removeListener('exit',shutdown);requireValue(closed,'LOKI_CHANNEL_CLEANUP_FAILED');
 }
}
export function grafanaRunUrl({runId,projectId,resultDigest,completedAt}){
 const at=Date.parse(completedAt);requireValue(Number.isFinite(at),'LOKI_RESULT_TIMESTAMP_INVALID');
 const q=new URLSearchParams({'var-DS_LOKI':'loki','var-project':projectId,'var-run':runId,'var-resultDigest':resultDigest,from:String(at-60000),to:String(at+300000)});
 return 'http://grafana.devops.local/d/security-manager-v2-candidate/devsecops-security-manager-v2-overview?'+q;
}
export function lokiDeliveryRecord(result,receipt,grafanaUrl,receiptSource){
 // Preparation-error Router receipts carry no httpStatus (no HTTP was
 // attempted); absent receipt fields normalize to null so the run record
 // embedding this object stays pure JSON for its audit digest.
 return {consumerId:'loki-candidate',automatic:true,sourceClassification:'REAL_CONTROLLED_EXECUTION',runId:result.runId,resultDigest:result.resultDigest,
  pushState:receipt.deliveryState,pushHttpStatus:receipt.httpStatus??null,receiptDigest:receipt.receiptDigest,httpRequestCount:receipt.httpRequestCount,
  queryState:'NOT_VERIFIED',state:'FAILED',reason:receipt.diagnosticCode??receipt.errorCategory??null,deliveryAt:receipt.timestamp,
  grafanaUrl,receiptSource};
}
export async function deliverRunToLoki(result,dir){
 requireValue(result.evidenceClass==='REAL'&&result.state==='COMPLETED'&&result.scannerExecuted===true&&result.evaluationCount===1,'LOKI_REAL_RESULT_REQUIRED');
 const artifactDirectory=path.join(dir,'artifact'),summary=JSON.parse(fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json')));
 const selected=summary.pluginResults.find(r=>r.pluginId===result.pluginId);
 requireValue(summary.runId===result.runId&&selected?.resultDigest===result.resultDigest,'LOKI_SELECTED_RESULT_BINDING');
 const output=path.join(dir,'loki-delivery');fs.mkdirSync(output,{mode:0o700});
 return withExistingLokiChannel(async()=>{
  const routed=await routeResultsWithLoki({run:{summary},artifactDirectory,expectedSealDigest:result.artifactDigest,
   definitions:[],expectedProjectId:summary.projectId,singlePluginId:result.pluginId,freshRunId:result.runId,
   lokiOutput:output,lokiTransport:createLokiTransport({mode:'real-http',targetId:'existing-security-loki-v1',timeoutMs:3000,maxAttempts:1,backoffMs:1})});
  const receipt=routed.lokiDelivery;save(path.join(output,'router-receipt.json'),routed);
  requireValue(receipt.runId===result.runId&&receipt.resultDigests[result.pluginId]===result.resultDigest,'LOKI_RECEIPT_BINDING');
  const base=lokiDeliveryRecord(result,receipt,grafanaRunUrl({...selected,completedAt:selected.completedAt}),path.relative(dir,path.join(output,'router-receipt.json')));
  if(receipt.deliveryState!=='ACKNOWLEDGED')return base;
  const at=BigInt(Date.parse(selected.completedAt))*1000000n;
  const selector='{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"}';
  const query=selector+' | json | runId='+JSON.stringify(result.runId)+' | resultDigest='+JSON.stringify(result.resultDigest);
  const route='/loki/api/v1/query_range?'+new URLSearchParams({query,start:String(at-1000000000n),end:String(at+1000000000n),limit:'5',direction:'forward'});
  let matches=[];
  for(let n=0;n<3;n++){
   const response=await get(route);requireValue(response.status==='success'&&response.data?.resultType==='streams','LOKI_QUERY_RESPONSE_INVALID');
   matches=response.data.result.flatMap(s=>s.values.map(v=>JSON.parse(v[1])));
   for(const e of matches){validateLokiEvent(e);requireValue(e.runId===result.runId&&e.pluginId===result.pluginId&&e.resultDigest===result.resultDigest&&e.policyDecision===result.policyDecision&&e.sourceClassification==='REAL_CONTROLLED_EXECUTION','LOKI_QUERY_RESULT_BINDING');}
   if(matches.length)break;await pause(300);
  }
  const proof={runId:result.runId,resultDigest:result.resultDigest,query,queriedAt:new Date().toISOString(),queryHttpStatus:200,
   matchedEvents:matches.length,sourceClassification:'REAL_CONTROLLED_EXECUTION',event:matches[0]??null};
  save(path.join(output,'query-proof.json'),{...proof,proofDigest:digest(proof)});
  return {...base,state:matches.length?'DELIVERED':'ACKNOWLEDGED',queryState:matches.length?'VERIFIED':'NOT_FOUND',reason:matches.length?null:'LOKI_QUERY_NOT_FOUND',queryAt:proof.queriedAt,queryHttpStatus:200,matchedEvents:matches.length};
 });
}
