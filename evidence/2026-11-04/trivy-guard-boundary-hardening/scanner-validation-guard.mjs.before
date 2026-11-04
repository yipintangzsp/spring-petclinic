// Explicit non-release entry point. The frozen production IO and its callers stay unchanged.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash, randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {scannerRefreshIO,verifyManifest} from './scanner-db-refresh.mjs';

export const GiB = 1024 ** 3;
export const validationLimits = Object.freeze({pollMs:100, maxSampleGapMs:1000, sampleTimeoutMs:500,
 termGraceMs:1000, killGraceMs:1000, maxLogBytes:1024 ** 2, maxRunMs:210000, minimumInodes:4096});
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const positive = x => Number.isSafeInteger(x) && x > 0;
const digest = x => /^sha256:[a-f0-9]{64}$/.test(x ?? '');
// Existing release-preflight stop line, not a tunable validation threshold.
export const validationHardFloor = capacity => Math.ceil(capacity * 0.15 + 8 * GiB);
export const productionRefreshRequirement = capacity => capacity * 0.15 + 12 * GiB;

export function assessValidationBudget(sample, budget, now = Date.now(), monitoring = false) {
 const blockers = [], domains = [];
 if (!sample || !Number.isFinite(sample.at) || now - sample.at < -5000 || now - sample.at > validationLimits.sampleTimeoutMs)
  blockers.push('FRESH_STORAGE_SAMPLE_REQUIRED');
 if (sample?.diskPressure !== false) blockers.push('DISK_PRESSURE_NOT_CONFIRMED_FALSE');
 if (sample?.unownedWriter !== false) blockers.push('WRITER_ISOLATION_NOT_PROVEN');
 if (sample?.ownerValid !== true) blockers.push('VALIDATION_OWNER_NOT_CONFIRMED');
 if (budget?.status !== 'PROVEN_CONSERVATIVE_UPPER_BOUND'
  || !['db','java-db'].every(kind=>digest(budget?.artifactDigests?.[kind]))
  || !/^[a-f0-9]{64}$/.test(budget?.evidenceSha256 ?? '') || !budget?.evidenceIdentity)
  blockers.push('REFRESH_PEAK_UPPER_BOUND_NOT_PROVEN');
 if (!Array.isArray(budget?.domains) || !budget.domains.length) blockers.push('BACKING_STORAGE_BUDGET_UNKNOWN');
 if (new Set(budget?.domains?.map(d => d.id)).size !== budget?.domains?.length) blockers.push('DUPLICATE_STORAGE_DOMAIN');
 if (!Array.isArray(sample?.domains) || sample.domains.length !== budget?.domains?.length)
  blockers.push('STORAGE_DOMAIN_COVERAGE_UNKNOWN');
 for (const b of budget?.domains ?? []) {
  const s = sample?.domains?.find(d => d.id === b.id);
  if (!s || !b.id || !b.identity || s.identity !== b.identity || !positive(b.capacityBytes)
   || s.capacityBytes !== b.capacityBytes || !Number.isSafeInteger(s.availableBytes) || s.availableBytes < 0
   || s.availableBytes > s.capacityBytes || !positive(s.inodesFree)) {
   blockers.push('STORAGE_IDENTITY_OR_MEASUREMENT_INVALID:' + b.id); continue;
  }
  // Every write allowance needs an independently reviewed bound, not a sampled maximum.
  if (!['peakAdditionalBytes','instantaneousWriteBytes','cleanupBytes','otherWriterBytes','peakAdditionalInodes']
   .every(k => positive(b[k])) || b.boundIncludesDownloadExtractionOldNewTemp !== true
   || b.boundIncludesScanAndReports !== true || b.cleanupProven !== true || b.backingAllocationProven !== true)
   blockers.push('INCOMPLETE_SPACE_OR_CLEANUP_PROOF:' + b.id);
  if (!(b.instantaneousWindowMs >= validationLimits.maxSampleGapMs + validationLimits.sampleTimeoutMs
   + validationLimits.termGraceMs + validationLimits.killGraceMs + validationLimits.pollMs))
   blockers.push('STOP_LATENCY_WRITE_BOUND_NOT_PROVEN:' + b.id);
  const hardFloorBytes = validationHardFloor(b.capacityBytes);
  const requiredBytes = hardFloorBytes + b.instantaneousWriteBytes + b.cleanupBytes + b.otherWriterBytes
   + (monitoring ? 0 : b.peakAdditionalBytes);
  if (!Number.isSafeInteger(requiredBytes)) blockers.push('INVALID_BUDGET_ARITHMETIC:' + b.id);
  else if (s.availableBytes < requiredBytes) blockers.push('INSUFFICIENT_SPACE:' + b.id);
  if (s.inodesFree < validationLimits.minimumInodes + b.peakAdditionalInodes) blockers.push('INSUFFICIENT_INODES:' + b.id);
  domains.push({id:b.id, identity:b.identity, availableBytes:s.availableBytes, capacityBytes:s.capacityBytes,
   hardFloorBytes, peakAdditionalBytes:b.peakAdditionalBytes, instantaneousWriteBytes:b.instantaneousWriteBytes,
   cleanupBytes:b.cleanupBytes, otherWriterBytes:b.otherWriterBytes, requiredBytes});
 }
 return {mode:'validation-only', allowed:blockers.length === 0, blockers, domains,
  productionGuardChanged:false, monitoredPeakIsNotABudget:true};
}

// A hash-bound, reviewed proof is a prerequisite. This loader does not certify its scientific validity.
export function loadValidationBudget(file, expectedSha256) {
 if (!/^[a-f0-9]{64}$/.test(expectedSha256 ?? '')) throw Error('REVIEWED_BUDGET_HASH_REQUIRED');
 const st=fs.lstatSync(file); if (!st.isFile() || st.isSymbolicLink() || st.size > 1024 ** 2) throw Error('INVALID_BUDGET_FILE');
 const bytes=fs.readFileSync(file);if (sha(bytes)!==expectedSha256) throw Error('REVIEWED_BUDGET_HASH_MISMATCH');
 const b=JSON.parse(bytes);return {...b,evidenceSha256:expectedSha256,evidenceIdentity:path.basename(file)};
}

export async function boundedSample(sample) {
 let timer;
 try {return await Promise.race([Promise.resolve().then(sample),new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(Error('MONITOR_TIMEOUT')),validationLimits.sampleTimeoutMs);
 })]);} finally {clearTimeout(timer);}
}

// Reads actual local allocation, never du/apparent-size or a synthetic quota. VM backing
// domains must additionally be supplied by their real observer; omitted domains block.
export function createLocalStorageSampler({domains,readState,readBacking=async()=>[]}) {
 if(!Array.isArray(domains)||!domains.length||typeof readState!=='function')throw Error('EXPLICIT_STORAGE_OBSERVER_REQUIRED');
 return async()=>{
  const state=await readState(),rows=[];
  for(const d of domains){
   if(!d.id||!path.isAbsolute(d.path))throw Error('INVALID_STORAGE_OBSERVER_PATH');
   const s=fs.statSync(d.path),f=fs.statfsSync(d.path,{bigint:true});
   const n=x=>{const value=Number(x);if(!Number.isSafeInteger(value))throw Error('UNSAFE_STORAGE_COUNTER');return value;};
   rows.push({id:d.id,identity:'dev:'+s.dev,capacityBytes:n(f.blocks*f.bsize),availableBytes:n(f.bavail*f.bsize),inodesFree:n(f.ffree)});
  }
  return {...state,at:Date.now(),domains:[...rows,...await readBacking()]};
 };
}

export async function createValidationWorkspace({parent, runId, sample, budget}) {
 if (!/^trivy-validation-[a-f0-9]{16}$/.test(runId ?? '')) throw Error('EXPLICIT_VALIDATION_RUN_ID_REQUIRED');
 const root=fs.realpathSync(parent), st=fs.lstatSync(parent);
 // No production cache, arbitrary existing directory, shared world-writable parent, or symlink cleanup.
 if (st.isSymbolicLink() || !st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o077)
  || !root.startsWith(fs.realpathSync(os.tmpdir()) + path.sep)) throw Error('PRIVATE_TEMP_PARENT_REQUIRED');
 budget=structuredClone(budget);
 const freeze=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;};freeze(budget);
 const assessment=assessValidationBudget(await boundedSample(sample),budget);
 if (!assessment.allowed) throw Error('VALIDATION_PREFLIGHT_BLOCKED:' + assessment.blockers.join(','));
 const directory=fs.mkdtempSync(path.join(root,runId+'-'));fs.chmodSync(directory,0o700);
 const identity=fs.statSync(directory), owner=randomBytes(24).toString('hex');
 const cacheDir=path.join(directory,'cache'),tempDir=path.join(directory,'tmp');
 fs.mkdirSync(cacheDir,0o700);fs.mkdirSync(tempDir,0o700);
 fs.writeFileSync(path.join(directory,'.owner'),owner,{mode:0o600,flag:'wx'});
 let active=false,cleanupUncertain=false;
 function assertOwned() {
  const st=fs.lstatSync(directory);
  const marker=fs.lstatSync(path.join(directory,'.owner'));
  if (st.isSymbolicLink() || st.dev!==identity.dev || st.ino!==identity.ino
   || !marker.isFile() || marker.isSymbolicLink()
   || fs.readFileSync(path.join(directory,'.owner'),'utf8')!==owner) throw Error('WORKSPACE_OWNERSHIP_LOST');
 }
 return {directory,cacheDir,tempDir,runId,budget,sample,assertOwned,
  begin(){assertOwned();if(active || cleanupUncertain)throw Error('VALIDATION_PROCESS_OR_CLEANUP_UNCERTAIN');active=true;},
  end(stopped){active=false;cleanupUncertain ||= !stopped;},
  cleanup(){assertOwned();if(active || cleanupUncertain)throw Error('CLEANUP_NOT_PROVEN_SAFE');
   fs.rmSync(directory,{recursive:true});if(fs.existsSync(directory))throw Error('WORKSPACE_CLEANUP_FAILED');
   return {ownedWorkspaceRemoved:true,productionCacheTouched:false};}
 };
}

const sleep = ms => new Promise(resolve=>setTimeout(resolve,ms));
function groupAlive(pid) {try{process.kill(-pid,0);return true;}catch(e){if(e.code==='ESRCH')return false;throw e;}}
async function stopGroup(pid) {
 for (const [signal,grace] of [['SIGTERM',validationLimits.termGraceMs],['SIGKILL',validationLimits.killGraceMs]]) {
  if (!groupAlive(pid)) return true;
  try{process.kill(-pid,signal);}catch(e){if(e.code!=='ESRCH')throw e;}
  const end=Date.now()+grace;while(groupAlive(pid)&&Date.now()<end)await sleep(25);
 }
 return !groupAlive(pid);
}

// Owned process group only, never `pkill trivy` or deletion in a production cache.
export async function runOwnedValidationCommand(workspace, {binary,args,env={},signal,timeoutMs=validationLimits.maxRunMs}) {
 if (!path.isAbsolute(binary) || !Array.isArray(args) || !positive(timeoutMs) || timeoutMs>validationLimits.maxRunMs)
  throw Error('INVALID_VALIDATION_COMMAND');
 if (Object.keys(env).some(k=>!['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','PATH'].includes(k)))
  throw Error('VALIDATION_ENVIRONMENT_OVERRIDE_DENIED');
 workspace.assertOwned();
 const before=await boundedSample(()=>workspace.sample({phase:'preflight'})),assessment=assessValidationBudget(before,workspace.budget);
 if (!assessment.allowed) throw Error('VALIDATION_PREFLIGHT_BLOCKED:' + assessment.blockers.join(','));
 if (signal?.aborted) throw Error('VALIDATION_CANCELLED');
 workspace.begin();
 let child,closed=false,exitStatus=null,commandSignal=null,error=null,stopped=false,logBytes=0;
 const chunks=[],samples=[before],started=Date.now();let lastSample=Date.now();
 try {
  child=spawn(binary,args,{cwd:workspace.directory,detached:true,stdio:['ignore','pipe','pipe'],
   env:{PATH:env.PATH ?? process.env.PATH,LANG:'C',...env,HOME:workspace.directory,TMPDIR:workspace.tempDir,
    TMP:workspace.tempDir,TEMP:workspace.tempDir,TRIVY_CACHE_DIR:workspace.cacheDir}});
  child.on('error',e=>{error='VALIDATION_SPAWN_FAILED:'+e.code;closed=true;});
  child.on('close',(code,s)=>{exitStatus=code;commandSignal=s;closed=true;});
  for (const stream of [child.stdout,child.stderr]) stream.on('data',b=>{
   logBytes+=b.length;if(logBytes<=validationLimits.maxLogBytes)chunks.push(b);else error='VALIDATION_LOG_LIMIT';
  });
  while (!closed && !error) {
   if(signal?.aborted){error='VALIDATION_CANCELLED';break;}
   if(Date.now()-started>timeoutMs){error='VALIDATION_TIMEOUT';break;}
   let current;try{current=await boundedSample(()=>workspace.sample({phase:'monitor'}));}catch{error='MONITOR_FAILED';break;}
   const at=Date.now();if(at-lastSample>validationLimits.maxSampleGapMs){error='MONITOR_SAMPLE_GAP';break;}lastSample=at;
   const a=assessValidationBudget(current,workspace.budget,at,true);samples.push(current);
   if(!a.allowed){error='MONITOR_UNSAFE:'+a.blockers.join(',');break;}
   for(const b of workspace.budget.domains){const initial=before.domains.find(d=>d.id===b.id),cur=current.domains.find(d=>d.id===b.id);
    if(initial.availableBytes-cur.availableBytes>b.peakAdditionalBytes+b.otherWriterBytes)error='REVIEWED_WRITE_BOUND_EXCEEDED';}
   await sleep(validationLimits.pollMs);
  }
 } catch(e){error=e.message;}
 finally {
  try{stopped=child?.pid ? await stopGroup(child.pid) : true;}catch{stopped=false;}
  // Reap the child before declaring cleanup safe. Descendants surviving the group check block deletion.
  const until=Date.now()+validationLimits.killGraceMs;while(child?.pid&&!closed&&Date.now()<until)await sleep(10);
  stopped=stopped&&(!child?.pid||closed);workspace.end(stopped);
 }
 let after;try{after=await boundedSample(()=>workspace.sample({phase:'final'}));}catch{error ||= 'FINAL_STORAGE_STATE_UNKNOWN';}
 if(after){const a=assessValidationBudget(after,workspace.budget,Date.now(),true);samples.push(after);if(!a.allowed)error ||= 'FINAL_STORAGE_UNSAFE';
  if(a.allowed)for(const b of workspace.budget.domains){const initial=before.domains.find(d=>d.id===b.id),cur=after.domains.find(d=>d.id===b.id);
   if(initial.availableBytes-cur.availableBytes>b.peakAdditionalBytes+b.otherWriterBytes)error ||= 'FINAL_REVIEWED_WRITE_BOUND_EXCEEDED';}}
 const receipt={mode:'validation-only',exitStatus,commandSignal,error,processGroupStopped:stopped,logBytes,
  samples,monitorIsPeakProof:false,release:0,rollout:0};
 if(!stopped)receipt.error='OWNED_PROCESS_CLEANUP_NOT_PROVEN';
 return {...receipt,log:Buffer.concat(chunks).toString('utf8')};
}

export function scannerDatabaseIO({mode='production',validation,...productionOptions}={}) {
 if(mode==='production') {
  if(validation!==undefined)throw Error('VALIDATION_CONFIG_IN_PRODUCTION_DENIED');
  return scannerRefreshIO(productionOptions);
 }
 if(mode!=='validation-only' || Object.keys(productionOptions).length)throw Error('EXPLICIT_VALIDATION_CONFIG_REQUIRED');
 if(!validation)throw Error('EXPLICIT_VALIDATION_CONFIG_REQUIRED');
 return createValidationRefreshIO(validation);
}

export function createValidationRefreshIO({workspace,binary,binarySha256,assertOwner,manifestProvider}) {
 if(!workspace || typeof assertOwner!=='function' || !/^[a-f0-9]{64}$/.test(binarySha256 ?? '')
  || !path.isAbsolute(binary) || sha(fs.readFileSync(binary))!==binarySha256)throw Error('VALIDATION_TOOL_OR_OWNER_NOT_PROVEN');
 // Explicit provider only: never inherit PACKAGE_HTTPS_PROXY or production transport configuration.
 const upstream=async kind=>{
  if(typeof manifestProvider!=='function')throw Error('EXPLICIT_VALIDATION_MANIFEST_PROVIDER_REQUIRED');
  const raw=await manifestProvider(kind),artifact=verifyManifest(kind,raw.bytes,raw.digest);
  if(artifact.digest!==workspace.budget.artifactDigests[kind])throw Error('REVIEWED_ARTIFACT_BINDING_MISMATCH');
  return artifact;
 };let lastReceipt;
 return {assertOwner:async()=>{workspace.assertOwned();await assertOwner();
   const a=assessValidationBudget(await boundedSample(workspace.sample),workspace.budget);
   if(!a.allowed)throw Error('VALIDATION_PREFLIGHT_BLOCKED:'+a.blockers.join(','));},
  upstream,
  async download(kind,artifact) {
   if(sha(fs.readFileSync(binary))!==binarySha256)throw Error('VALIDATION_BINARY_IDENTITY_CHANGED');
   if(!['db','java-db'].includes(kind) || artifact.kind!==kind || artifact.digest!==workspace.budget.artifactDigests[kind]
    || artifact.repository!==`ghcr.nju.edu.cn/aquasecurity/trivy-${kind}@${artifact.digest}`)
    throw Error('REVIEWED_ARTIFACT_BINDING_MISMATCH');
   await assertOwner();
   lastReceipt=await runOwnedValidationCommand(workspace,{binary,args:['image',
    kind==='db'?'--download-db-only':'--download-java-db-only',
    kind==='db'?'--db-repository':'--java-db-repository',artifact.repository,
    '--cache-dir',workspace.cacheDir,'--timeout','3m','--no-progress'],
    env:{HTTP_PROXY:'',HTTPS_PROXY:'',ALL_PROXY:'',NO_PROXY:'ghcr.nju.edu.cn'}});
   if(lastReceipt.error || lastReceipt.exitStatus!==0)throw Error(lastReceipt.error ?? 'VALIDATION_TRIVY_EXIT_'+lastReceipt.exitStatus);
   return lastReceipt.log;
  },
  read(kind){if(!['db','java-db'].includes(kind))throw Error('INVALID_DATABASE_KIND');workspace.assertOwned();
   return JSON.parse(fs.readFileSync(path.join(workspace.cacheDir,kind,'metadata.json')));},
  receipt(){return lastReceipt;}
 };
}
