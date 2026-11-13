import fs from 'node:fs';
import {spawn,spawnSync} from 'node:child_process';
import {collectRuntimeFacts} from './collector.mjs';
import {executionPayload} from './projection.mjs';
import {sha,fail} from '../summary-v2/codec.mjs';
import {mergeKyvernoPackets} from './kyverno-observer.mjs';
import {captureSbomParent} from './sbom-execute.mjs';

// Executes the ORIGINAL command, not an adapter or recreated scanner. The
// observer uses an inherited anonymous pipe; no decrypted content hits disk.
export async function captureStage({sourceId,command,binding,env=process.env,cwd=process.cwd(),onOutput=()=>{},buildInput}){
  if(sourceId==='sbom')return captureSbomParent({sourceId,command,binding,env,cwd,onOutput,buildInput});
  if(sourceId==='sops'&&!env.ISOLATED_BOUNDARY_CONTEXT)fail('SOPS collection requires existing isolated executor boundary; production Secret access forbidden');
  if(sourceId==='sops'){
    const guard=new URL('../testing/',import.meta.url).pathname;
    const check=spawnSync('python3',['-B','-c',
      "import sys,os;sys.path.insert(0,sys.argv[1]);from isolated_sops_executor import validate_execution_environment;p=validate_execution_environment(os.environ);assert p.name=='MIN_RBAC_EXECUTOR' and p.fixture_age_file and p.fixture_input_root",guard],
      {cwd,env,stdio:['ignore','ignore','ignore'],timeout:10000});
    if(check.status!==0)fail('SOPS isolated MIN_RBAC boundary validation failed before Gate execution');
  }
  const observer=new URL('./observe.mjs',import.meta.url).pathname;
  const child=spawn('/bin/sh',['-c',command],{cwd,env:{...env,RUNTIME_FACT_SOURCE:sourceId,
    NODE_OPTIONS:[env.NODE_OPTIONS,'--import='+observer].filter(Boolean).join(' ')},stdio:['ignore','pipe','pipe','pipe']});
  let stdout='',stderr='',raw='',overflow=false,errorClass=null;
  const limit=24*1024*1024;
  const add=(name,b)=>{if(Buffer.byteLength(stdout)+Buffer.byteLength(stderr)+Buffer.byteLength(raw)+b.length>limit){overflow=true;child.kill('SIGTERM');return;}
    if(name==='raw')raw+=b;else{if(name==='stdout')stdout+=b;else stderr+=b;onOutput(name,b);}};
  child.stdout.on('data',b=>add('stdout',b));child.stderr.on('data',b=>add('stderr',b));child.stdio[3].on('data',b=>add('raw',b));
  child.on('error',e=>{errorClass=e.code??e.name;});
  const completion=await new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
  if(overflow)fail('runtime observation buffer exceeded; no truncated facts accepted');
  const packets=raw.trim()?raw.trim().split('\n').map(x=>JSON.parse(x)):[];
  // Current specialized source commands are one Node Gate each. Any accidental
  // duplicate observer is rejected rather than choosing a convenient packet.
  if(['sops','falco-baseline','falco-final','kubescape','gitleaks','zap','cosign'].includes(sourceId)&&packets.length!==1)fail('specialized source observation absent or duplicated');
  const combined=['semgrep-command-audit','trivy'].includes(sourceId);
  if(combined&&(packets.length<1||packets.length>2))fail('Combined command parent observations absent/duplicated');
  const observation=combined?{adapterPayload:{schema:1,stage:'parent',complete:true,command,operations:packets.map(p=>p.adapterPayload)}}:sourceId==='kyverno'?mergeKyvernoPackets(packets):packets[0],payload=executionPayload({sourceId,command,exitStatus:completion.code,stdout,stderr,observation});
  const envelope=collectRuntimeFacts({sourceId,binding,execution:{command,exitStatus:completion.code,signal:completion.signal,errorClass},payload,
    evidence:[{kind:'ACTUAL_PROCESS_EXECUTION',stdoutSha256:sha(stdout),stderrSha256:sha(stderr),observerPackets:packets.length,
      events:observation?.events??[],sampleWindows:observation?.adapterPayload?.observations?.samples?.map(s=>({
        windowEndMs:s.windowEndMs,windowStartMs:s.windowEndMs-15000,querySince:s.querySince,
        startedAtMs:s.startedAtMs,logCompletedAtMs:s.logCompletedAtMs,completedAtMs:s.completedAtMs}))??[],
      sourcePayloadClass:observation?'PASSIVE_IN_MEMORY_ORIGINAL_GATE_OBSERVATIONS':'ORIGINAL_COMMAND_EXIT_OBSERVATIONS'}]});
  return {envelope,exitStatus:completion.code,signal:completion.signal,stdout,stderr};
}
