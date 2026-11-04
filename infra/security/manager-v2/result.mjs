import fs from 'node:fs';import path from 'node:path';
import {evaluateAsync} from '../policy/engine.mjs';
import {canonical,digest,sha,freeze,fail} from '../summary-v2/codec.mjs';
import {identity} from './config.mjs';
export function policyOwner(config){
 const claims=new Set(),counts={};
 return Object.freeze({counts:()=>({...counts}),async evaluateOnce(id,facts){
  identity(id);if(claims.has(id))fail('duplicate Policy evaluation');claims.add(id);counts[id]=1;
  const before=canonical(facts),snapshot=JSON.parse(before);let evaluation;
  try{
   const result=await evaluateAsync(snapshot,config.policyConfig);
   // Match the existing owner projection: optional tool traces may contain
   // undefined diagnostics or private payloads and are not Summary metadata.
   evaluation=Object.fromEntries(['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides','status','decision'].map(k=>[k,structuredClone(result[k])]));
  }catch(e){
   if(!String(e.message).startsWith('POLICY_ERROR:'))throw e;
   evaluation={status:'POLICY_ERROR',decision:null,error:e.message};
  }
  if(canonical(snapshot)!==before||canonical(facts)!==before)fail('raw facts mutated');
  // Engine decision metadata stays in this object, shared by Gate/Summary.
  return freeze({policyVersion:config.policyVersion,enginePolicyVersion:config.policyConfig.policyVersion,policySource:config.policySource,securityLevel:config.securityLevel,profile:config.profile,effectivePolicy:config.effectivePolicy,appliedOverrides:config.appliedOverrides,
   evaluation,evaluationCount:1,factDigest:digest(facts)});
 }});
}
export function sealResult(body){return freeze({...body,resultDigest:digest(body)});}
export function verifyResult(result){
 const statuses=['COMPLETED','DISABLED','SKIPPED','NOT_CONFIGURED','UNSUPPORTED','POLICY_ERROR','ERROR'];
 if(result?.schemaVersion!==1||result.kind!=='CandidatePluginResult'||!statuses.includes(result.executionStatus)||![null,'PASS','WARN','FAIL'].includes(result.policyDecision)||![0,1].includes(result.evaluationCount)||!Array.isArray(result.evidenceRefs))fail('result contract');
 for(const k of ['runId','projectId','pluginId'])identity(result[k]);
 for(const k of ['inputDigest','configDigest','effectiveConfigDigest','contextDigest'])if(!/^[a-f0-9]{64}$/.test(result[k]))fail('result digest contract');
 if(result.executionStatus==='COMPLETED'){
  if(result.policyDecision===null||result.evaluationCount!==1||result.policy?.evaluation?.decision!==result.policyDecision||result.evidenceRefs.length===0||![result.rawReportDigest,result.factDigest].every(x=>/^[a-f0-9]{64}$/.test(x)))fail('completed result evidence');
 }else if(result.policyDecision!==null)fail('nonexecution cannot claim Policy decision');
 const {resultDigest,...body}=result;if(digest(body)!==resultDigest)fail('result digest mismatch');return true;
}
// Exclusive, owner-private candidate directory. Read-only files plus digest
// verification provide tamper evidence, not privileged-host/WORM guarantees.
export function artifactStore(directory){
 const dir=path.resolve(directory);if(fs.existsSync(dir))fail('candidate history already exists');
 const parent=path.dirname(dir);if(fs.realpathSync(parent)!==parent)fail('artifact parent symlink');
 const ps=fs.statSync(parent);if(ps.uid!==process.getuid?.()||(ps.mode&0o022)!==0)fail('artifact parent ownership/mode');
 fs.mkdirSync(dir,{mode:0o700});const original=fs.lstatSync(dir),files={};let sealed=false;
 const check=()=>{const s=fs.lstatSync(dir);if(s.isSymbolicLink()||s.ino!==original.ino||s.dev!==original.dev||s.uid!==original.uid)fail('artifact directory replaced');};
 const write=(name,bytes)=>{
  if(sealed||!/^[-a-zA-Z0-9_.]+\.json$/.test(name)||name==='security-summary.json')fail('artifact write forbidden');check();
  const fd=fs.openSync(path.join(dir,name),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
  try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);if(fs.fstatSync(fd).nlink!==1)fail('artifact hardlink');}finally{fs.closeSync(fd);}check();
  files[name]={sha256:sha(bytes),bytes:Buffer.byteLength(bytes)};return files[name];
 };
 const put=(name,value)=>write(name,canonical(value)+'\n');
 return Object.freeze({directory:dir,put,putRaw(name,text){if(typeof text!=='string')fail('raw bytes');JSON.parse(text);return write(name,text);},finish(){
  if(sealed)fail('artifact already sealed');const manifest={schemaVersion:1,kind:'CandidateArtifactSeal',productionEvidence:false,files:structuredClone(files)};
  put('candidate-seal.json',manifest);sealed=true;return freeze({sealDigest:digest(manifest),files:manifest.files});
 }});
}
export function verifyArtifact(directory,expectedSealDigest){
 const read=name=>{const fd=fs.openSync(path.join(directory,name),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{if(!fs.fstatSync(fd).isFile())fail('artifact type');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}};
 const seal=JSON.parse(read('candidate-seal.json'));if(digest(seal)!==expectedSealDigest)fail('artifact seal mismatch');
 if(seal.kind!=='CandidateArtifactSeal'||seal.productionEvidence!==false)fail('artifact identity');
 for(const [name,expected]of Object.entries(seal.files)){
  if(!/^[-a-zA-Z0-9_.]+\.json$/.test(name))fail('artifact path');const b=read(name);
  if(sha(b)!==expected.sha256||b.length!==expected.bytes)fail('artifact corruption');
  if(name.endsWith('.result.json'))verifyResult(JSON.parse(b));
 }
 return true;
}
