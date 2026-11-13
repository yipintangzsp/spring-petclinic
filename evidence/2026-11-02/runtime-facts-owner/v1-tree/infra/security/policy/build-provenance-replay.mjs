// CONTROLLED_REPLAY collector for unchanged producer/attestation scripts. Not imported by the Policy Engine.
// No real process, registry, Maven, Buildx, credential or source-file read is performed by the replay.
import fs from 'node:fs';import vm from 'node:vm';import path from 'node:path';import crypto from 'node:crypto';
import {verifyEnvelope} from '../provenance/contract.mjs';import {buildPredicateType,validateBuildStatement} from '../provenance/build-contract.mjs';
const clean=p=>fs.readFileSync(p,'utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
const scripts={package:clean('infra/security/provenance/build-record.mjs'),image:clean('infra/security/provenance/build-record.mjs'),'harbor-copy':clean('infra/observability/publish-artifacts.mjs'),create:clean('infra/security/provenance/build-attestation.mjs'),verify:clean('infra/security/provenance/build-attestation.mjs')},runtime=clean('infra/security/scanner-runtime.mjs');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export async function replayBuildStage(raw){
 const trace=[],writes={},counts={};let complete=true;
 const need=(map,key)=>{if(!map||!Object.hasOwn(map,key)){complete=false;throw Error('Uncaptured replay observation: '+key);}return map[key];};
 const io=key=>{const r=need(raw.io,key);trace.push({type:'io',key,...(r.error?{error:r.error}:{})});if(r.error)throw Error(r.error);};
 const readFile=(p,encoding)=>{
  if(p==='infra/security/scanner-tools.json'){if(raw.runtime.manifestReadError)throw Error(raw.runtime.manifestReadError);return need(raw.runtime,'manifest');}
  if(p==='infra/security/tools-lock.json'){if(raw.runtime.lockReadError)throw Error(raw.runtime.lockReadError);return JSON.stringify({supplyChain:{scanner_manifest_sha256:need(raw.runtime,'expectedManifestSha256')}});}
  const toolRoot=JSON.parse(raw.runtime.manifest).root;
  if(p.startsWith(toolRoot+'/')){const r=need(raw.runtime.tools,p.slice(toolRoot.length+1));if(r.error)throw Error(r.error);return {measuredSha256:need(r,'sha256'),observedPath:p};}
  const index=counts['read:'+p]??0;counts['read:'+p]=index+1;const records=need(raw.files,p),r=Array.isArray(records)?need(records,index):records;
  trace.push({type:'file-read',path:p,index,...(r.error?{error:r.error}:{})});if(r.error)throw Error(r.error);
  if(encoding)return need(r,'value');
  if(r.measuredSha256)return {measuredSha256:r.measuredSha256,observedPath:p};
  return need(r,'value');
 };
 const fsFake={readFileSync:readFile,mkdirSync:p=>io('mkdir:'+p),mkdtempSync:()=>{io('temp-create');return '/tmp/build-attestation-frozen';},chmodSync:()=>io('temp-chmod'),rmSync:()=>io('temp-remove'),existsSync:()=>{io('temp-stat');return raw.tempExists===true;},readlinkSync:p=>need(raw.runtime.tools,p.slice(JSON.parse(raw.runtime.manifest).root.length+1)).symlink,
  writeFileSync:(p,v)=>{if(typeof v!=='string'&&!ArrayBuffer.isView(v))throw TypeError('Invalid write data');io('write:'+p);if(p.startsWith('.devsecops/')||p.startsWith('target/platform/'))writes[p]=String(v);},
  readdirSync:p=>{const index=counts['walk:'+p]??0;counts['walk:'+p]=index+1;let r=need(raw.walk,p);if(Array.isArray(r)&&Array.isArray(r[0]))r=need(r,index);if(r.error)throw Error(r.error);trace.push({type:'directory-read',path:p,index});return r.map(e=>({name:e.name,isDirectory:()=>e.type==='directory',isFile:()=>e.type==='file',isSymbolicLink:()=>e.type==='symlink'}));}
 };
 const spawnSync=(bin,args)=>{
  if(bin==='kubectl'){const r=need(raw.runtime,'lease');trace.push({type:'lease-query',args:[...args],result:structuredClone(r)});return r;}
  const name=path.basename(bin),index=counts['command:'+name]??0;counts['command:'+name]=index+1;const r=need(need(raw.commands,name),index);need(r,'status');trace.push({type:'command',tool:name,args:[...args],result:structuredClone(r)});return r;
 };
 const fetch=async(url,options={})=>{
  const key=(options.method??'GET')+' '+url,index=counts[key]??0;counts[key]=index+1;const r=need(need(raw.network,key),index);
  trace.push({type:'network',method:options.method??'GET',url,status:r.status??null,error:r.error??null});if(r.error)throw Error(r.error);
  const bytes=Buffer.from(r.bytes??JSON.stringify(r.json??{}));
  return {status:r.status,ok:r.status>=200&&r.status<300,headers:{get:k=>r.headers?.[k]??null},json:async()=>{if(r.jsonError)throw Error('Malformed response JSON');return r.json;},arrayBuffer:async()=>bytes,body:{cancel:async()=>{}}};
 };
 let clock=raw.now;class FrozenDate extends Date{constructor(...a){super(...(a.length?a:[clock++]));}static now(){return clock;}}
 const cryptoFake={createHash:algorithm=>({update:value=>({digest:encoding=>{if(value?.measuredSha256){trace.push({type:'checksum-observation',path:value.observedPath,sha256:value.measuredSha256,freshSourceHashComputed:false});return value.measuredSha256;}return crypto.createHash(algorithm).update(value).digest(encoding);}})})};
 const context={fs:fsFake,path,os:{tmpdir:()=>'/tmp'},crypto:cryptoFake,spawnSync,fetch,Buffer,URL,AbortSignal,Date:FrozenDate,process:{argv:['node','frozen',raw.phase],env:{...raw.environment}},verifyEnvelope:(...args)=>{try{const result=verifyEnvelope(...args);trace.push({type:'existing-dsse-verifier',verified:true});return result;}catch(error){trace.push({type:'existing-dsse-verifier',verified:false,diagnostic:error.message});throw error;}},buildPredicateType,validateBuildStatement:(statement,expected)=>{try{const result=validateBuildStatement(statement,expected);trace.push({type:'existing-build-validator',valid:true,expected:structuredClone(expected),buildFacts:structuredClone(result)});return result;}catch(error){trace.push({type:'existing-build-validator',valid:false,expected:structuredClone(expected),diagnostic:error.message});throw error;}},console:{log:()=>{}},setTimeout:fn=>{fn();},waitGitLabReady:()=>{throw Error('Out-of-scope GitLab operation');}};
 let exitCode=0,error;
 try{if(raw.phase!=='harbor-copy'){const h=vm.runInNewContext('(function(){'+runtime+';return {requireLease,verifyTools,toolchain};})()',context);Object.assign(context,h);}await vm.runInNewContext('(async()=>{'+(scripts[raw.phase]??scripts.package)+'})()',context);}catch(e){exitCode=1;error=e.message;}
 const facts={schema:1,source:'build-provenance-verification',policyVersion:'baseline-v1',phase:raw.phase,classification:'CONTROLLED_REPLAY',complete,execution:{exitCode,...(error?{diagnostic:error}:{})},inputIdentity:{...structuredClone(raw.identity),requestedVerification:{image:raw.environment.BUILD_PROVENANCE_IMAGE,commit:raw.environment.BUILD_SOURCE_COMMIT,repository:raw.environment.BUILD_SOURCE_REPOSITORY,builder:raw.environment.BUILD_BUILDER_IDENTITY,buildNumber:raw.environment.BUILD_SOURCE_NUMBER}},observations:trace,artifacts:writes};
 return {facts,oldDecision:complete?(exitCode===0?'PASS':'FAIL'):null,writes,trace};
}
