#!/usr/bin/env node
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
import {runCandidate} from './core.mjs';import {registry} from './registry.mjs';import {routeResults} from './router.mjs';
import {fail} from '../summary-v2/codec.mjs';
export function parameters(argv,env){
 const options={};for(let i=0;i<argv.length;i+=2){const key=argv[i];if(!['--config','--inputs','--output','--project','--run-id'].includes(key)||options[key]!==undefined||!argv[i+1]||argv[i+1].startsWith('--'))fail('invalid/duplicate CLI argument');options[key]=argv[i+1];}
 if(!options['--output']||!options['--project']||!options['--run-id'])fail('output/project/run-id required');
 const config=options['--config']?JSON.parse(fs.readFileSync(options['--config'])):{};config.security??={};
 const mapping={SECURITY_ENABLED:'enabled',GLOBAL_MODE:'globalMode',SECURITY_LEVEL:'securityLevel',PROFILE:'profile',POLICY_VERSION:'policyVersion'};
 for(const [name,key]of Object.entries(mapping))if(env[name]!==undefined){let value=env[name];if(name==='SECURITY_ENABLED'){if(!['true','false'].includes(value))fail('SECURITY_ENABLED must be true|false');value=value==='true';}config.security[key]=value;}
 if(env.PLUGIN_SELECTION!==undefined){
  const ids=registry().ids(),s=env.PLUGIN_SELECTION,selected=s==='all'?ids:s==='none'?[]:s.split(',');
  if(new Set(selected).size!==selected.length||selected.some(x=>!ids.includes(x)))fail('invalid plugin selection');
  config.security.plugins=Object.fromEntries(ids.map(id=>[id,{enabled:selected.includes(id)}]));
 }
 const inputs=options['--inputs']?JSON.parse(fs.readFileSync(options['--inputs'])):{};
 return {config,inputs,projectId:options['--project'],runId:options['--run-id'],output:path.resolve(options['--output']),context:{platform:process.platform,capabilities:options['--inputs']?{SECURITY_REPORTS:{state:'AVAILABLE'}}:{}}};
}
export async function main(argv=process.argv.slice(2),env=process.env){
 const options=parameters(argv,env),run=await runCandidate(options);
 const routed=routeResults({run,artifactDirectory:options.output,expectedSealDigest:run.artifact.sealDigest,definitions:[{consumerId:'dry-run',enabled:true,requiredInputs:['SECURITY_SUMMARY'],inputSchema:'SecuritySummaryCandidate/v1',publish:'dry-run',verify:'digest/v1',errorPolicy:'RECORD_AND_BLOCK'}]});
 console.log(JSON.stringify({managerVersion:run.summary.managerVersion,runId:run.summary.runId,overallStatus:run.summary.overallStatus,candidateBuildAllowed:run.summary.candidateBuildAllowed,promotion:run.summary.promotion,sealDigest:run.artifact.sealDigest,router:routed,release:0,rollout:0}));
 return run.summary.candidateBuildAllowed?0:1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{process.exitCode=await main();}catch{console.error('POLICY_ERROR: candidate invocation rejected; no production action');process.exitCode=2;}}
