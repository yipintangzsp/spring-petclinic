// One-shot FIFO: raw synthetic SOPS observations go straight to the sole owner
// process, never to a workspace/report file or a listening network service.
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import crypto from 'node:crypto';import {execFileSync} from 'node:child_process';
import {validateRuntimeFacts} from './collector.mjs';import {fail} from '../summary-v2/codec.mjs';
export function validateIsolatedPacket(packet,binding,nonce){
 if(packet?.nonce!==nonce||packet.executionScope!=='CONTROLLED_ISOLATED_RUNTIME'||packet.scenario!=='POSITIVE')fail('Isolated transport scope/scenario mismatch');
 const guard=packet.guard;
 if(guard?.status!=='ACCEPTED'||guard.profile!=='MIN_RBAC_EXECUTOR'||guard.server!=='https://security-test-sops-control-plane:6443'||guard.kubeSystemUID!=='54f300a4-5f1b-4e1e-86a1-d173e5a402d8'||guard.audit?.child_executions!==1||guard.temporaryDirectoryRemoved!==true)fail('Isolated real minimum-RBAC guard evidence missing');
 const envelope=validateRuntimeFacts(packet.envelope,binding);
 if(envelope.sourceId!=='sops'||envelope.execution.exitStatus!==packet.oldExit||envelope.facts.raw.readOnly!==true||envelope.facts.raw.expectedTargetCount!==4||!envelope.evidence.some(e=>e.executionScope==='CONTROLLED_ISOLATED_RUNTIME'&&e.canonicalCurrentResult===true))fail('Isolated canonical fact contract missing');
 return {envelope,oldExit:packet.oldExit,guard};
}
export async function receiveIsolatedSops({binding,output,timeoutMs=180000}){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'runtime-isolated-facts-'));fs.chmodSync(directory,0o700);
 const fifo=path.join(directory,'sops.fifo'),request=path.join(output,'isolated-sops-request.json'),nonce=crypto.randomBytes(24).toString('hex');
 let fd,timer,poller,closed=false;
 try{
  execFileSync('mkfifo',['-m','600',fifo]);
  fd=fs.openSync(fifo,fs.constants.O_RDWR|fs.constants.O_NONBLOCK);
  fs.writeFileSync(request,JSON.stringify({schema:1,binding,nonce,fifo,executionScope:'CONTROLLED_ISOLATED_RUNTIME'}),{mode:0o600,flag:'wx'});
  console.log(JSON.stringify({sourceId:'sops',status:'AWAITING_APPROVED_ISOLATED_FACTS',build:binding.build}));
  const packet=await new Promise((resolve,reject)=>{
   let buffer='';timer=setTimeout(()=>reject(Error('RUNTIME_OBSERVATION_BLOCKED: approved isolated packet timeout')),timeoutMs);
   poller=setInterval(()=>{try{
    const chunk=Buffer.alloc(65536);let n;
    try{n=fs.readSync(fd,chunk,0,chunk.length,null);}catch(e){if(e.code==='EAGAIN')return;throw e;}
    buffer+=chunk.subarray(0,n).toString('utf8');
    if(Buffer.byteLength(buffer)>4*1024*1024)throw Error('Isolated fact packet over limit');
    if(buffer.includes('\n')){const lines=buffer.trim().split('\n');if(lines.length!==1)throw Error('Isolated extra message rejected');resolve(JSON.parse(lines[0]));}
   }catch(e){reject(e);}},50);
  });
  return validateIsolatedPacket(packet,binding,nonce);
 }finally{
  clearTimeout(timer);clearInterval(poller);if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(request))fs.unlinkSync(request);fs.rmSync(directory,{recursive:true,force:true});closed=!fs.existsSync(directory);
  fs.writeFileSync(path.join(output,'isolated-channel-cleanup.json'),JSON.stringify({transport:'ANONYMOUS_STDIO_AND_PRIVATE_ONE_SHOT_FIFO',rawPayloadWrittenToDisk:false,networkListenerCreated:false,cleanupComplete:closed}));
 }
}
