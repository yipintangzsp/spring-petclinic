import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';
import {pathToFileURL} from 'node:url';
const allowed=new Set(['LANG','LC_ALL','TZ','HOME','KUBECONFIG','PATH','TMPDIR','XDG_CACHE_HOME','PYTHONDONTWRITEBYTECODE','ISOLATED_BOUNDARY_CONTEXT']);
if(Object.keys(process.env).some(k=>!allowed.has(k)))throw Error('UNEXPECTED_ENVIRONMENT');
if(fs.existsSync(path.join(process.env.HOME,'.kube')))throw Error('DEFAULT_CONFIG_PRESENT');
const dir=process.cwd();const gatePath=path.join(dir,'infra/security/secrets-gate.mjs');
const source=fs.readFileSync(gatePath,'utf8');
const modules=['node:fs','node:util','node:crypto','node:net','node:os','node:child_process'];const imports={};
for(const id of modules)imports[id]=await import(id);
// Actual runtime import does only its frozen manifest hash prerequisite; no Lease/Secret/child call.
const runtime=await import(pathToFileURL(path.join(dir,'infra/security/scanner-runtime.mjs')));
const exports=['run','read','kube','requireLease','verifyTools','toolchain'];
if(!exports.every(x=>Object.hasOwn(runtime,x)))throw Error('RUNTIME_EXPORT_MISSING');
const gate=new vm.SourceTextModule(source,{identifier:pathToFileURL(gatePath).href});
await gate.link(async id=>{
 const actual=id==='./scanner-runtime.mjs'?runtime:imports[id];if(!actual)throw Error('UNEXPECTED_GATE_IMPORT '+id);
 const names=Object.keys(actual);return new vm.SyntheticModule(names,function(){for(const n of names)this.setExport(n,actual[n]);});
});
if(gate.status!=='linked')throw Error('GATE_LINK_FAILED');
// Do not evaluate Gate: evaluation would immediately require a real Lease.
const result={classification:'REAL_NODE_STARTUP_ONLY_WITH_SYNTHETIC_GUARD_IDENTITY',nodeVersion:process.version,arch:process.arch,platform:process.platform,nodePath:process.execPath,cwd:dir,moduleMode:'ESM .mjs',builtinModulesLoaded:modules,runtimeImported:true,frozenManifestHashCheckExecuted:true,gateParsed:true,gateLinkStatus:gate.status,gateBodyEvaluated:false,gateSha256:crypto.createHash('sha256').update(source).digest('hex'),sanitizedEnvironmentNames:Object.keys(process.env).sort(),defaultHomeConfigAbsent:true,kubernetesApiCalls:0,gateExecutions:0,policyExecutions:0};
fs.writeFileSync('/fixture/results/startup.json',JSON.stringify(result,null,2));
console.log('NODE_MJS_STARTUP_SENTINEL_OK');
