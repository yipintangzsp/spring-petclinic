import fs from 'node:fs';import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';import {allowCosignCommand,allowCosignRegistry} from './cosign-boundary.mjs';
const c=JSON.parse(fs.readFileSync(process.env.RUNTIME_COSIGN_BOUNDARY)),spawn=cp.spawnSync,fetch0=globalThis.fetch;
cp.spawnSync=function(bin,args,options){allowCosignCommand(bin,args,c);return spawn(bin,args,options);};
for(const n of ['spawn','exec','execSync','execFile','execFileSync','fork'])cp[n]=()=>{throw Error('COSIGN_OTHER_PROCESS_DENIED');};
globalThis.fetch=async function(url,options={}){allowCosignRegistry(url,options,c);return fetch0(url,options);};syncBuiltinESMExports();
