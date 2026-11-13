// Enforce bounded external capabilities; no scanner return values are replaced.
import fs from 'node:fs';import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';import {authorizeProcess,validateContract} from './side-effect-contract.mjs';
const c=validateContract(JSON.parse(fs.readFileSync(process.env.RUNTIME_SIDE_EFFECT_CONTRACT))),sp=cp.spawnSync,as=cp.spawn;
cp.spawnSync=function(bin,args,opts){authorizeProcess(bin,args,c);return sp(bin,args,opts);};
cp.spawn=function(bin,args,opts){authorizeProcess(bin,args,c);return as(bin,args,opts);};
for(const method of ['exec','execSync','execFile','execFileSync','fork'])cp[method]=()=>{throw Error('FORBIDDEN_UNSCOPED_PROCESS_API');};
globalThis.fetch=()=>{throw Error('FORBIDDEN_EXTERNAL_HTTP_FROM_LOCAL_SCANNER_PARENT');};
syncBuiltinESMExports();
