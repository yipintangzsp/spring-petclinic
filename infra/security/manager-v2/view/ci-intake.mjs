// Versioned CI-only UNIX intake. No browser routes, shell parameters or caller configuration.
import fs from 'node:fs';import http from 'node:http';import path from 'node:path';import {timingSafeEqual} from 'node:crypto';
import {submit,getRun} from './actions.mjs';import {projectControls} from './controls.mjs';
export const ciCapabilityFile=new URL('../../../../.devsecops/security-view-ci-capability-v1.json',import.meta.url);
const projects=()=>JSON.parse(fs.readFileSync(new URL('../ci/projects.json',import.meta.url)));
const fault=(code,status=403)=>Object.assign(Error(code),{code,status});
function readCapability(){const fd=fs.openSync(ciCapabilityFile,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(s.uid!==process.getuid()||(s.mode&0o077)||s.size>8192||!s.isFile()||s.nlink!==1)throw fault('CI_CAPABILITY_STORAGE');return JSON.parse(fs.readFileSync(fd));}finally{fs.closeSync(fd);}}
export function validateCI(v,c){
 const keys=['projectId','sourceRepository','commitSha','ciProvider','jobId','buildId','trigger','pluginId','scenarioId'];
 if(!v||Object.keys(v).sort().join(',')!==keys.sort().join(','))throw fault('CI_FIELDS_REJECTED',400);
 const p=projects()[v.projectId];if(!p||v.projectId!==c.projectId||v.pluginId!==p.pluginId||v.scenarioId!==p.scenarioId||v.sourceRepository!==p.sourceRepository||v.ciProvider!==p.ciProvider||v.jobId!==p.jobId||v.trigger!=='gitlab-webhook'||v.commitSha!==c.commitSha||!Number.isSafeInteger(v.buildId)||v.buildId!==c.buildId||!/^[a-f0-9]{40}$/.test(v.commitSha))throw fault('CI_SCOPE_REJECTED');
 return {...v,buildUrl:p.jobUrl+v.buildId+'/',sourceScope:p.executionScope,...(p.sourceMode?{sourceMode:p.sourceMode}:{}),...(c.retryOf?{retryOf:c.retryOf}:{})};
}
export function startCIIntake(){
 if(!fs.existsSync(ciCapabilityFile))return null;const c=readCapability();if(c.expiresAt<=Date.now())return null;
 const socket=path.join(c.stateDirectory,'ci.sock'),claim=path.join(c.stateDirectory,'ci-claim.json');
 if(fs.existsSync(socket))throw fault('CI_SOCKET_ALREADY_EXISTS');
 const st=fs.lstatSync(c.stateDirectory);if(!st.isDirectory()||st.uid!==process.getuid()||(st.mode&0o077))throw fault('CI_SOCKET_DIRECTORY_UNSAFE');
 const s=http.createServer(async(req,res)=>{
  const send=(code,v)=>{res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(v));};
  try{
   const cap=readCapability(),expected='Bearer '+cap.token,auth=req.headers.authorization;
   if(cap.expiresAt<=Date.now()||typeof auth!=='string'||auth.length!==expected.length||!timingSafeEqual(Buffer.from(auth),Buffer.from(expected)))throw fault('CI_IDENTITY_REJECTED');
   if(req.method==='POST'&&req.url==='/v1/runs'){
    if(req.headers['content-type']!=='application/json')throw fault('CI_JSON_REQUIRED',415);
    let size=0;const chunks=[];for await(const b of req){size+=b.length;if(size>2048)throw fault('CI_INPUT_LIMIT',413);chunks.push(b);}
    const context=validateCI(JSON.parse(Buffer.concat(chunks)),cap),control=projectControls(context.projectId);
    if(!control.effectiveEnabled)return send(409,{state:'DISABLED',reason:'GLOBAL_PROJECT_OR_PLUGIN_DISABLED',scannerExecuted:false,evaluationCount:0});
    if(fs.existsSync(claim))throw fault('CI_ONE_RUN_BUDGET_USED',409);
    const fd=fs.openSync(claim,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    try{const r=submit({pluginId:context.pluginId,scenarioId:context.scenarioId},context);fs.writeFileSync(fd,JSON.stringify({runId:r.runId,projectId:context.projectId}));fs.fsyncSync(fd);return send(202,{runId:r.runId,state:r.state,resultUrl:'http://security.devops.local:17862/#live-validation'});}finally{fs.closeSync(fd);}
   }
   if(req.method==='GET'&&/^\/v1\/runs\/web-[a-f0-9-]{36}$/.test(req.url)){
    if(!fs.existsSync(claim))throw fault('CI_RUN_NOT_OWNED');const own=JSON.parse(fs.readFileSync(claim));if(req.url!=='/v1/runs/'+own.runId)throw fault('CI_RUN_NOT_OWNED');const r=getRun(own.runId);if(r.projectId!==cap.projectId||r.pluginId!=='gitleaks')throw fault('CI_RESULT_BINDING');
    return send(200,Object.fromEntries(['runId','projectId','state','evidenceClass','scannerExitCode','policyDecision','evaluationCount','resultDigest','artifactDigest','ciContext','lokiDelivery','completedAt','reason','findingsCount','sourceMode','sourceCommitSha','sourceSnapshotSha256','sourceTreeOid','sourceFileCount','sourceExpandedBytes','sourceBudgetExceptionHits','sourceCleanup'].map(k=>[k,r[k]??null])));
   }
   throw fault('CI_ROUTE_REJECTED',404);
  }catch(e){send(e.status??400,{error:/^[A-Z_]+$/.test(e.code??'')?e.code:'CI_REQUEST_REJECTED'});}
 });s.requestTimeout=5000;s.listen(socket,()=>fs.chmodSync(socket,0o600));s.on('error',e=>console.error('CI_SOCKET_ERROR',e.code));return {server:s,socket};
}
