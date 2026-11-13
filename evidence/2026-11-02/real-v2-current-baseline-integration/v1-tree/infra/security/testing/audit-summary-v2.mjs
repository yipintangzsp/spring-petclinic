import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {evaluateAsync} from '../policy/engine.mjs';
const root = new URL('../../../',import.meta.url).pathname.replace(/\/$/,''),base=path.join(root,'evidence/2026-11-02/summary-v2-migration');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const write=(name,value)=>fs.writeFileSync(path.join(base,name),JSON.stringify(value,null,2)+'\n');
const before=JSON.parse(fs.readFileSync(path.join(base,'before-sha256.json'))),drift=[];
for(const [relative,hash]of Object.entries(before))if(!fs.existsSync(path.join(root,relative))||sha(fs.readFileSync(path.join(root,relative)))!==hash)drift.push(relative);
const v1=JSON.parse(fs.readFileSync(path.join(base,'V1_IDENTITY.json'))),snapshotDrift=[];
for(const [relative,{sha256}]of Object.entries(v1.files))if(sha(fs.readFileSync(path.join(base,'v1-tree',relative)))!==sha256)snapshotDrift.push(relative);
let refs=0;const locked=new Map(),failures=[];
for(const file of fs.readdirSync(path.join(root,'infra/security/policy/versions')).filter(n=>n.endsWith('.json'))){
 const contract=JSON.parse(fs.readFileSync(path.join(root,'infra/security/policy/versions',file)));
 for(const [relative,hash]of Object.entries(contract.sourceHashes??{})){
  refs++;locked.set(relative,hash);if(sha(fs.readFileSync(path.join(root,relative)))!==hash)failures.push({contract:file,relative});
 }
}
const prior=JSON.parse(fs.readFileSync(path.join(root,'evidence/2026-11-02/summary-integration-readiness-audit/source-integrity.json'))),authoritativeFailures=[];
for(const record of prior.checks)if(sha(fs.readFileSync(path.join(root,record.path)))!==record.expected)authoritativeFailures.push({lock:record.lock,path:record.path});
write('source-preservation.json',{beforeFiles:Object.keys(before).length,existingChanged:drift,lockedReferences:refs,lockedDistinct:locked.size,lockedFailures:failures,
 authoritativeReferences:prior.checks.length,authoritativeDistinct:new Set(prior.checks.map(x=>x.path)).size,authoritativeFailures,
 snapshotFiles:Object.keys(v1.files).length,snapshotDrift,oldProductionActivatedChanges:0,acceptedV1ContractChanged:false,scannerAdapterPolicySemanticsChanged:false});

// REPORT-PROJECTION probes, deliberately NOT actual production executions or
// real findings. They show that a success report is not a complete adapter input.
const requirements=[
 ['sops','infra/security/secrets-gate.mjs','infra/security/policy/sops-evidence.mjs',['prerequisites','targets[*].decrypt','targets[*].actual','targets[*].after','rbac','reportWriteSucceeded']],
 ['kyverno','infra/security/rbac-contract.mjs + infra/security/admission-gate.mjs','infra/security/policy/kyverno-parent.mjs',['configuration','observations.rbac[*] raw command results','observations.policy','observations.probes','observations.owners','observations.workloads']],
 ['kubescape','infra/security/governance/kubescape.mjs','infra/security/policy/kubescape-parent.mjs',['lock','observations.hashes','observations.lease','observations.scans','observations.cleanup']],
 ['falco-baseline','infra/security/runtime/health.mjs','infra/security/policy/falco-parent.mjs',['configuration','observations','raw time/sample binding']],
 ['falco-final','infra/security/runtime/health.mjs','infra/security/policy/falco-parent.mjs',['configuration','observations','raw time/sample binding']],
 ['cosign','infra/security/signing.mjs','infra/security/policy/cosign-parent.mjs',['stage','configuration','environment','runtime','files','commands','io']],
 ['defectdojo','infra/security/governance/defectdojo.mjs','infra/security/policy/dojo-parent.mjs',['files','target','api request/response observations','credentials presence only']]
];
const probes=[];
for(const [source,production,adapter,required]of requirements){
 const input={component:source,status:'success',raw:{status:'success',source:'c'.repeat(40)}},before=JSON.stringify(input),r=await evaluateAsync(input);
 probes.push({source,classification:'SYNTHETIC_REPORT_PROJECTION_ONLY_NOT_REAL_EXECUTION',production,adapter,required,
  engineStatus:r.status,engineDecision:r.decision,inputUnchanged:JSON.stringify(input)===before,runtimeCollector:'NOT_IMPLEMENTED',
  frozenCompatibilityStatus:'UNCHANGED; these probes do not alter prior adapter verification',
  blocker:'Native success/status records cannot substitute for the adapter-required raw execution observations'});
}
write('runtime-observation-gaps.json',{classification:'IMPLEMENTATION_READINESS_NOT_SOURCE_COMPATIBILITY_REVALIDATION',probes,
 allProbesExplicitlyAbsent:probes.every(x=>['NOT_CONFIGURED','NOT_TESTED'].includes(x.engineStatus)&&x.engineDecision===null),
 observationCaptureIsPossible:true,
 existingPrecedent:'evidence/2026-11-02/sops-authoritative-differential-02/observer.mjs',
 limitation:'Existing SOPS observer is fixture-specific and includes fault-injection hooks. It is NOT a general production collector and has not been installed here.',
 minimalFix:'Implement and differentially test passive in-memory observation capture for each missing source; remove fixture injection from a production collector; preserve original arguments, process exits, IO outcomes and protected data handling; then atomically migrate the actual owners and consumers.'});

write('activation-state.json',{summaryProducer:'V1',securityManager:'V1',jenkins:'V1',promotion:'V1',regression:'V1',
 candidateModulesOnly:true,actualSecuritySummaryWritten:false,productionGateChanged:false,release:0,rollout:0,
 migrationVerdict:'INCOMPLETE',blockers:[
  'Runtime observation-to-frozen-fact capture is not implemented for the complete canonical source set. No source result artifact can yet be emitted by the real Manager without missing observations.',
  'Current Jenkins/Manager do not hand source receipts to Gate. Candidate owner count proof is owner-process scoped, not a whole real pipeline proof.',
  'Actual Promotion and Regression consumers have NOT been migrated. New candidate integrity contract is NOT an accepted active contract. Old Promotion ignores additive policy metadata.',
  'Legacy Summary field snapshot is supplied by controlled fixtures. A production pre-approval field capture path and emission/archive/transport handoff remain unwired.'
 ]});
write('consumer-coverage.json',{promotion:{legacyRegression:'EXECUTED_UNCHANGED',v2RuntimeMigration:'NOT_TESTED_NOT_WIRED'},regression:{legacyNodeExitScope:'UNCHANGED',v2RuntimeMigration:'NOT_TESTED_NOT_WIRED'},
 jenkins:{archiveGlob:'STATIC_PATH_CHECK',realExecution:'NOT_TESTED'},
 loki:{existingJsonFieldProjection:'CONTROLLED_JSON_SELECTOR_COMPATIBILITY_ONLY',liveParserTransport:'NOT_TESTED'},
 grafana:{fourteenExistingJsonSelectors:'CONTROLLED_FIELD_EQUALITY',liveQuery:'NOT_TESTED'},
 otherDirectConsumers:'Original sign-approve/promote both still use the unchanged gateEvidence. No candidate metadata is active.'});
if(drift.length||snapshotDrift.length||failures.length||authoritativeFailures.length||!probes.every(x=>x.inputUnchanged))process.exitCode=1;
console.log(JSON.stringify({existingChanged:drift.length,snapshotDrift:snapshotDrift.length,lockedReferences:refs,lockedDistinct:locked.size,lockedFailures:failures.length,reportProjectionMissing:probes.length,verdict:'INCOMPLETE'}));
