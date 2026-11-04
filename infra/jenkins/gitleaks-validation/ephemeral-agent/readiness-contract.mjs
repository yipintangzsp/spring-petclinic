// OFFLINE STATIC/FIXTURE CONTRACTS ONLY. These are not an admission controller,
// provisioner, approval signature verifier, or replacement for frozen CI guards.
import crypto from 'node:crypto';
import {AGENT,JOB,RELEASE,nodeName,validateBinding,validateFixtureFiles} from './plan.mjs';
const must=(x,m)=>{if(!x)throw Error('READINESS_REJECTED: '+m);};
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const exact=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export const MANIFEST='e8677d348192d378de0314c4ce5edc102514dbf0ec28c13aa850d510bf514b5a';
export function fixtureFiles(id){
 must(['clean','secret'].includes(id),'fixture allowlist');
 // This string is generated solely as non-issued passive scanner input. Never
 // authenticate with it or contact an issuer. It is not a production credential.
 const invalid=['ghp','aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cF0iL2oR4'].join('_');
 return [{path:'src/validation.txt',type:'file',executable:false,
  content:id==='clean'?'validation message = hello clinic\n':
   '# Disposable scanner canary; never issued; never authenticate\ngithub_token = "'+invalid+'"\n'}];
}
export function contentManifest(files){
 must(Array.isArray(files)&&files.every(f=>f&&exact(Object.keys(f).sort(),['path','type','executable','content'].sort())&&typeof f.content==='string'),'fixture data field allowlist');
 validateFixtureFiles(files.map(f=>({path:f.path,type:f.type,executable:f.executable,bytes:Buffer.byteLength(f.content)})));
 return files.map(f=>({path:f.path,sha256:hash(f.content),bytes:Buffer.byteLength(f.content)})).sort((a,b)=>a.path.localeCompare(b.path));
}
export function fixtureContract(id){
 const manifest=contentManifest(fixtureFiles(id));
 return {schemaVersion:1,projectId:'java-fixture',profile:'java-web',case:id,
  source:'TRUSTED_CANDIDATE_GENERATOR_NON_ISSUED_DISPOSABLE_DATA',
  sourceGenerator:'infra/jenkins/gitleaks-validation/ephemeral-agent/readiness-contract.mjs',
  contentDigest:hash(JSON.stringify(manifest)),manifest,scanScope:'PASSIVE_DIRECTORY_ONLY',gitHistory:false,
  trustedConfig:'EXISTING_GITLEAKS_BUILTIN_DEFAULT',expected:{scannerExit:id==='clean'?0:1,oldGate:id==='clean'?'PASS':'FAIL',policy:id==='clean'?'PASS':'FAIL'},
  retention:{source:'PINNED_SYNTHETIC_GENERATOR_AND_IMAGE_INPUT_RETAINED_WITH_REVIEWED_VERSION; RUN_COPY_REMOVED',archive:'REDACTED_REPORT_AND_DIGESTS_ONLY',plaintextCanaryArchive:false},
  approval:{status:'PENDING_APPROVAL',subject:null,reference:null},
  classification:'CANDIDATE_DATA_CONTRACT_NOT_CI_AUTHORIZATION'};
}
export function validateFixtureApproval(c,files,approval){
 const expected=fixtureContract(c?.case);
 must(exact(c,expected),'pinned project/profile/revision/scope/retention changed');
 must(exact(contentManifest(files),c.manifest),'fixture revision/content mismatch');
 // This checks a proposed approval record's structure only. Real signature and
 // trusted management provenance remain NOT_IMPLEMENTED; never authorize CI here.
 must(approval&&exact(Object.keys(approval).sort(),['status','subject','reference','projectId','case','contentDigest','managerManifest'].sort()),'approval field allowlist');
 must(approval.status==='APPROVED'&&typeof approval.subject==='string'&&approval.subject.length>0&&typeof approval.reference==='string'&&approval.reference.length>0,'fixture not authorized');
 must(approval.projectId===c.projectId&&approval.case===c.case&&approval.contentDigest===c.contentDigest&&approval.managerManifest===MANIFEST,'approval binding');
 return {classification:'OFFLINE_APPROVAL_SCHEMA_ONLY',runtimeAuthorization:false};
}
export function validateRunBinding(b,tombstones){
 validateBinding(b);must(Array.isArray(tombstones),'trusted never-reuse registry absent');
 must(!tombstones.includes(b.agent),'Node name reused');
 return {physicalNode:nodeName(b.runBuild,b.runNonce),logicalLabel:AGENT,job:JOB,release:RELEASE,secretTTL:null,
  classification:'STATIC_BINDING_NOT_LIVE_AUTHORIZATION',frozenEntryCompatible:false};
}
export function safeArchiveMetadata(x){
 const allowed=['classification','job','build','runId','nodeName','podUid','secretUid','imageDigest','managerManifest','fixtureContentDigest','resultDigest','cleanupStatus'];
 must(x&&Object.keys(x).every(k=>allowed.includes(k)),'credential or unknown archive field');
 must(Object.values(x).every(v=>typeof v==='string'||Number.isSafeInteger(v)),'nested or non-scalar archive value');
 const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
 for(const [k,v] of Object.entries(x)){
  if(k==='classification')must(['STATIC','FIXTURE','REAL_CONTROLLED_EXECUTION'].includes(v),'archive classification');
  else if(k==='job')must(v===JOB,'archive job');
  else if(k==='build')must(Number.isSafeInteger(v)&&v>0&&v<=999999999,'archive build');
  else if(k==='runId')must(/^ci-[1-9][0-9]{0,8}-[a-f0-9]{8}$/.test(v),'archive runId');
  else if(k==='nodeName')must(/^gitleaks-v2-[1-9][0-9]{0,8}-[a-f0-9]{24}$/.test(v),'archive Node name');
  else if(['secretUid','podUid'].includes(k))must(uuid.test(v),'archive UID');
  else if(k==='cleanupStatus')must(['NOT_TESTED','CLEANUP_INCOMPLETE','VERIFIED'].includes(v),'archive cleanup status');
  else if(k==='imageDigest')must(/^127\.0\.0\.1:30050\/platform-security\/gitleaks-validation-agent@sha256:[a-f0-9]{64}$/.test(v),'archive image digest');
  else must(/^[a-f0-9]{64}$/.test(v),'archive digest');
 }
 return {...x};
}
export function assessResources(x){
 must(x?.node==='devops'&&x.arch==='arm64'&&x.pressure===false,'node/architecture/pressure');
 for(const k of ['freeRequestedCpu','freeRequestedMemoryBytes','minAvailableMemoryBytes','freeEphemeralBytes'])must(Number.isFinite(x[k])&&x[k]>=0,'unknown resource '+k);
 must(x.freeRequestedCpu>=0.25&&x.freeRequestedMemoryBytes>=512*2**20,'insufficient requests');
 // A conservative readiness-test budget, not a new production scheduling rule.
 must(x.minAvailableMemoryBytes>=768*2**20+2*2**30,'production memory headroom');
 for(const k of ['quotaFree','peakMemoryVerified','pidLimitVerified','imageCached','imageUnpackBudgetVerified','ephemeralPeakVerified'])must(x[k]===true,'unproven '+k);
 must(x.freeEphemeralBytes>=x.requiredPeakEphemeralBytes&&Number.isFinite(x.requiredPeakEphemeralBytes)&&x.requiredPeakEphemeralBytes>=256*2**20,'unknown disk peak');
 return {classification:'STATIC_PRECONDITION_CHECK_ONLY',runtime:'NOT_TESTED'};
}
export function assessNetwork(x){
 for(const k of ['denyAllPresent','exactControllerSelector','dnsOnly','noSourceDownload','noProxy','policyImplementationObserved','tlsVerified','apiMetadataDenialVerified'])must(x?.[k]===true,'unproven network '+k);
 must(x.transport==='WEBSOCKET'&&x.fallback===null,'transport fallback');
 return {classification:'STATIC_PRECONDITION_CHECK_ONLY',runtime:'NOT_VERIFIED'};
}
export function authorizeRuntime(){throw Error('CI_EXECUTION_NOT_READY: candidate contracts cannot provision or authorize execution');}
