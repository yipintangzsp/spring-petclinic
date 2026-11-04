// Explicit non-release entry point. The frozen production IO and its callers stay unchanged.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash, randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
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
  productionGuardChanged:false, monitoredPeakIsNotABudget:true, executionAuthorized:false};
}

// A hash-bound, reviewed proof is a prerequisite. This loader does not certify its scientific validity.
const pathHelper=fileURLToPath(new URL('./scanner-validation-paths.py',import.meta.url));
// Native roots, never HOME/TMPDIR selected by the validation caller.
const nativeTempRoots=(()=>{
 const candidates=['/tmp',...(process.platform==='linux'?['/var/tmp']:[])];
 if(process.platform==='darwin'){
  try{candidates.push(execFileSync('/usr/bin/getconf',['DARWIN_USER_TEMP_DIR'],{
   encoding:'utf8',timeout:5000,env:{PATH:'/usr/bin:/bin',LANG:'C'}}).trim());}catch{/* /tmp remains available; never fall back to caller HOME. */}
 }
 return candidates.flatMap(p=>{try{return [fs.realpathSync(p)];}catch{return [];}});
})();
function pathOperation(request) {
 let result;
 try {result=JSON.parse(execFileSync('/usr/bin/python3',['-I',pathHelper],{
  input:JSON.stringify(request),encoding:'utf8',timeout:5000,maxBuffer:1048576,
  env:{PATH:'/usr/bin:/bin',LANG:'C',PYTHONDONTWRITEBYTECODE:'1'},stdio:['pipe','pipe','pipe']}));}
 catch(e){try{result=JSON.parse(e.stdout);}catch{throw Error('UNSUPPORTED_OR_FAILED_DESCRIPTOR_PATH_HELPER');}}
 if(result?.ok!==true)throw Error('VALIDATION_PATH_REJECTED:'+result?.error);
 return result.result;
}
export function loadValidationBudget(file, expectedSha256) {
 if (!/^[a-f0-9]{64}$/.test(expectedSha256 ?? '')) throw Error('REVIEWED_BUDGET_HASH_REQUIRED');
 const bytes=pathOperation({operation:'read-budget',file:path.resolve(file)}).text;
 if(sha(bytes)!==expectedSha256)throw Error('REVIEWED_BUDGET_HASH_MISMATCH');
 return {...JSON.parse(bytes),evidenceSha256:expectedSha256,evidenceIdentity:path.basename(file)};
}

export async function boundedSample(sample) {
 let timer;const started=performance.now();
 try {const result=await Promise.race([Promise.resolve().then(sample),new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(Error('MONITOR_TIMEOUT')),validationLimits.sampleTimeoutMs);
 })]);if(performance.now()-started>validationLimits.sampleTimeoutMs)throw Error('MONITOR_TIMEOUT');return result;
 } finally {clearTimeout(timer);}
}

// Reads actual local allocation, never du/apparent-size or a synthetic quota. VM backing
// domains are observational only. This caller-supplied observer cannot authorize
// execution; the workspace independently inventories its own descriptor-bound paths.
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
  return {...state,at:Date.now(),domains:[...rows,...await readBacking()],observationOnly:true,executionAuthorized:false};
 };
}

// No cgroup/filesystem sandbox has been implemented or authenticated in the current
// Darwin/Linux environment. A process group does NOT authorize scanner execution.
// Fail closed before spawn, rather than return a false process-tree cleanup receipt.
const workspaces=new WeakSet();
export function validationCapabilities() {
 return {platform:process.platform,arch:process.arch,processIsolation:'UNSUPPORTED',
  descendantContainment:'UNSUPPORTED',writeConfinement:'UNSUPPORTED',
  mountIdentity:process.platform==='linux'?'PROC_MOUNTINFO':'INCOMPLETE',
  reason:process.platform==='darwin'?'NO_VERIFIED_DARWIN_EXECUTION_SANDBOX':'NO_VERIFIED_DELEGATED_CGROUP_AND_FILESYSTEM_SANDBOX',
  executionReady:false};
}
export async function createValidationWorkspace({parent, runId, sample, budget}) {
 if (!/^trivy-validation-[a-f0-9]{16}$/.test(runId ?? '')) throw Error('EXPLICIT_VALIDATION_RUN_ID_REQUIRED');
 const root=fs.realpathSync(parent), st=fs.lstatSync(parent);
 const nativeRoot=nativeTempRoots.some(tempRoot=>{const relative=path.relative(tempRoot,root);
  return relative&&relative!=='..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);});
 if(st.isSymbolicLink() || !st.isDirectory() || st.uid!==process.getuid() || (st.mode & 0o077)
  || !nativeRoot)
  throw Error('PRIVATE_TEMP_PARENT_REQUIRED');
 const freeze=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;};
 budget=freeze(structuredClone(budget));
 const assessment=assessValidationBudget(await boundedSample(sample),budget);
 if(!assessment.allowed)throw Error('VALIDATION_PREFLIGHT_BLOCKED:'+assessment.blockers.join(','));
 const name=runId+'-'+randomBytes(8).toString('hex'),owner=randomBytes(24).toString('hex');
 const parentIdentity={dev:st.dev,ino:st.ino};
 const created=pathOperation({operation:'create',parent:root,parentIdentity,name,owner});
 const directory=path.join(root,name),cacheDir=path.join(directory,'cache'),tempDir=path.join(directory,'tmp');
 const request={root:directory,identity:created.identity,parentIdentity,owner,directories:created.directories};
 const operate=(operation,extra={})=>pathOperation({...request,...extra,operation});
 const initial=operate('inspect');let active=false,cleanupUncertain=false,consumed=false;
 const storageKey=x=>JSON.stringify(x.domains.map(d=>({identity:d.identity,mounts:d.mounts,capacityBytes:d.capacityBytes})));
 function inspect(){const state=operate('inspect');if(storageKey(state)!==storageKey(initial))throw Error('STORAGE_DOMAIN_CHANGED');return state;}
 const workspace={directory,cacheDir,tempDir,runId,budget,sample,
  reportDir:path.join(directory,'report'),evidenceDir:path.join(directory,'evidence'),logDir:path.join(directory,'logs'),manifestDir:path.join(directory,'manifests'),
  assertOwned(){inspect();},
  observeStorage(){return inspect();},
  preflight(){const storage=inspect(),storageBlockers=[];
   for(const d of storage.domains){
    const matches=budget.domains.filter(b=>b.identity===d.identity&&b.capacityBytes===d.capacityBytes);
    if(matches.length!==1)storageBlockers.push('UNREGISTERED_ACTUAL_STORAGE_DOMAIN:'+d.identity);
    if(d.availableBytes<validationHardFloor(d.capacityBytes))storageBlockers.push('BELOW_HARD_FLOOR:'+d.identity);
    if(d.inodesFree<validationLimits.minimumInodes)storageBlockers.push('INSUFFICIENT_ACTUAL_INODES:'+d.identity);
   }
   return {status:'NOT_READY',capabilities:validationCapabilities(),
   actualStorage:storage,callerDeclaredDomainsAreAuthorization:false,
   blockers:['PROCESS_ISOLATION_UNSUPPORTED','DESCENDANT_CLEANUP_UNPROVEN','FILESYSTEM_WRITE_CONFINEMENT_UNSUPPORTED',
    ...(storage.mountIdentitySupported?[]:['MOUNT_IDENTITY_INCOMPLETE']),
    ...storageBlockers,'PHYSICAL_BACKING_AND_PEAK_BUDGET_NOT_AUTHENTICATED'],executionAuthorized:false};},
  readMetadata(kind){if(!['db','java-db'].includes(kind))throw Error('INVALID_DATABASE_KIND');inspect();
   return JSON.parse(operate('read',{relative:'cache/'+kind+'/metadata.json'}).text);},
  readRelative(relative){inspect();return operate('read',{relative}).text;},
  consume(){if(consumed)throw Error('VALIDATION_SINGLE_RUN_ALREADY_CONSUMED');consumed=true;},
  begin(){inspect();if(active||cleanupUncertain)throw Error('VALIDATION_PROCESS_OR_CLEANUP_UNCERTAIN');active=true;},
  end(stopped){active=false;cleanupUncertain ||= !stopped;},
  cleanup(){inspect();if(active||cleanupUncertain)throw Error('CLEANUP_NOT_PROVEN_SAFE');
   const result=operate('cleanup');return {ownedWorkspaceRemoved:result.ownedWorkspaceRemoved,productionCacheTouched:false};}
 };
 workspaces.add(workspace);return Object.freeze(workspace);
}

export async function runOwnedValidationCommand(workspace, {binary,args,env={},signal,timeoutMs=validationLimits.maxRunMs,purpose='validation-only'}) {
 if(!workspaces.has(workspace))throw Error('AUTHENTIC_GUARD_WORKSPACE_REQUIRED');
 if(!path.isAbsolute(binary)||!Array.isArray(args)||!positive(timeoutMs)||timeoutMs>validationLimits.maxRunMs)
  throw Error('INVALID_VALIDATION_COMMAND');
 if(Object.keys(env).some(k=>!['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','PATH'].includes(k)))
  throw Error('VALIDATION_ENVIRONMENT_OVERRIDE_DENIED');
 if(purpose!=='validation-only')throw Error('RELEASE_PROMOTION_ROLLOUT_DENIED');
 workspace.assertOwned();workspace.consume();
 const preflight=workspace.preflight();
 return {mode:'validation-only',status:'NOT_READY',exitStatus:null,commandSignal:null,
  error:signal?.aborted?'VALIDATION_CANCELLED':'UNSUPPORTED_PROCESS_AND_FILESYSTEM_ISOLATION',
  commandStarted:false,processGroupStopped:null,descendantsStopped:null,
  residualProcessRisk:'NO_CHILD_STARTED_BY_THIS_ATTEMPT; EXISTING_OR_FOREIGN_PROCESSES_NOT_CLAIMED_STOPPED',
  capabilities:preflight.capabilities,preflight,samples:[],logBytes:0,log:'',monitorIsPeakProof:false,
  release:0,rollout:0};
}

export function scannerDatabaseIO({mode='production',validation,...productionOptions}={}) {
 if(mode==='production') {
  if(validation!==undefined)throw Error('VALIDATION_CONFIG_IN_PRODUCTION_DENIED');
  return scannerRefreshIO(productionOptions);
 }
 if(!['validation-only','validation'].includes(mode) || Object.keys(productionOptions).length)throw Error('EXPLICIT_VALIDATION_CONFIG_REQUIRED');
 if(!validation)throw Error('EXPLICIT_VALIDATION_CONFIG_REQUIRED');
 return createValidationRefreshIO(validation);
}

export function createValidationRefreshIO({workspace,binary,binarySha256,assertOwner,manifestProvider}) {
 if(!workspaces.has(workspace) || typeof assertOwner!=='function' || !/^[a-f0-9]{64}$/.test(binarySha256 ?? '')
  || !path.isAbsolute(binary) || sha(fs.readFileSync(binary))!==binarySha256)throw Error('VALIDATION_TOOL_OR_OWNER_NOT_PROVEN');
 // Explicit provider only: never inherit PACKAGE_HTTPS_PROXY or production transport configuration.
 const upstream=async kind=>{
  if(typeof manifestProvider!=='function')throw Error('EXPLICIT_VALIDATION_MANIFEST_PROVIDER_REQUIRED');
  if(workspace.preflight().status!=='READY')throw Error('VALIDATION_PREFLIGHT_NOT_READY');
  const raw=await manifestProvider(kind),artifact=verifyManifest(kind,raw.bytes,raw.digest);
  if(artifact.digest!==workspace.budget.artifactDigests[kind])throw Error('REVIEWED_ARTIFACT_BINDING_MISMATCH');
  return artifact;
 };let lastReceipt;
 return {assertOwner:async()=>{workspace.assertOwned();await assertOwner();
   if(workspace.preflight().status!=='READY')throw Error('VALIDATION_PREFLIGHT_NOT_READY');
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
   return workspace.readMetadata(kind);},
  receipt(){return lastReceipt;}
 };
}
