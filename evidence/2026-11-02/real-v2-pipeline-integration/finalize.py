"""Finalize this stopped integration attempt; no scanners/Policy/remote calls.

Hash-only validation and disposition. Does not rerun or rewrite old evidence.
"""
import hashlib
import json
import pathlib
import re

base = pathlib.Path(__file__).resolve().parent
root = base.parents[2]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text())
def write(name, value):
    (base/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')

before=load(base/'before-sha256.json')
changed=[name for name,h in before.items() if not (root/name).is_file() or sha(root/name)!=h]
v1=load(base/'V1_IDENTITY.json')
snapshot_errors=[name for name,x in v1['files'].items() if sha(base/'v1-tree'/name)!=x['sha256']]
references=load(root/'evidence/2026-11-02/summary-integration-readiness-audit/source-integrity.json')['checks']
reference_errors=[{'path':x['path'],'lock':x['lock']} for x in references if sha(root/x['path'])!=x['expected']]
active=load(base/'ACTIVE_V1_IDENTITY.json')
active_errors=[name for name,x in active['files'].items() if x['exists'] and sha(base/'active-v1-tree'/name)!=x['sha256']]
live=load(base/'live-jenkins-baseline.json')['jobs'][0]
workspace=load(base/'live-workspace-hashes.json')['workspaces'][0]
clock=load(base/'falco-clock-preflight.json')
drifts=[r for r in clock['records'] if not r['match']]
assert clock['cleanClockControlsMatch'] and len(drifts)==2
assert all(r['oldDecision']=='FAIL' and r['standardDecision']=='PASS' and r['rawPreserved'] for r in drifts)
assert not changed and not snapshot_errors and not reference_errors and not active_errors

write('preservation.json',{'existingProtectedFiles':len(before),'existingChanged':changed,
 'localSnapshotFiles':len(v1['files']),'localSnapshotErrors':snapshot_errors,
 'activeSnapshotFiles':len(active['files']),'activeSnapshotErrors':active_errors,
 'authoritativeHashReferences':len(references),'authoritativeDistinctFiles':len({r['path'] for r in references}),'authoritativeHashFailures':reference_errors,
 'sourceSemanticFilesModified':False,'adaptersModified':False,'baselineV1Modified':False,'existingCandidateChanged':False,
 'knownHostsModified':False,'strictHostKeyChecking':True,'secretValuesRead':False,
 'existingCompatibilityEvidenceRewritten':False,'productionFilesModified':0,'jenkinsConfigurationModified':False,
 'newJenkinsBuildsTriggered':0,'approval':0,'signing':0,'promotion':0,'release':0,'rollout':0})
inventory=load(root/'evidence/2026-11-02/policy-evaluation-scope-design/evaluation-scope.design.json')['sourcePartition']
write('runtime-source-coverage.json',{'canonicalSourceCount':16,'inventoryLabelCount':18,
 'sources':[{'sourceId':source,'realRuntimeFactsCaptured':False,'evaluationCount':None,'resultIdentity':None,
  'status':'FAILED_COMPATIBILITY_PREFLIGHT' if source in ['falco-baseline','falco-final'] else 'NOT_TESTED',
  'reason':'Controlled delayed-IO evidence produces legacy FAIL versus standard PASS' if source in ['falco-baseline','falco-final'] else 'Integration stopped before a real pipeline execution'} for source in inventory['canonicalPreApprovalSources']],
 'nullCountMeaning':'NOT_OBSERVED; not a fabricated runtime count of zero or one',
 'alias':inventory['aliases'],'postScope':inventory['postScopeSources'],
 'historical270Modules':'Retained only as HISTORICAL_ARCHIVE in live-jenkins-baseline.json; not new V2 source facts'})
write('owner-trace.json',{'classification':'REAL_CONFIG_AND_SOURCE_READ_ONLY_TRACE_NOT_RUNTIME_INTEGRATION',
 'job':live['job'],'scriptPath':live['scriptPath'],'scmBranches':live['scmBranches'],'library':active['libraries'],
 'managerOrchestrationPoint':'vars/securityManager.groovy: call(Map cfg), plan loop, provenance/build-provenance helpers and Security Gate stage',
 'expectedCanonicalSources':16,'planModules':14,'optionalHelperSources':2,
 'outerChecks':'Snapshot Before and Read Only Release Verification remain in Jenkinsfile.security-audit outside Manager',
 'actualPolicyEvaluationOwner':None,'candidateOwner':'infra/security/summary-v2/owner.mjs:createSourceOwner, not deployed or invoked by job',
 'engineExistsInRealWorkspace':workspace['files']['infra/security/policy/engine.mjs']['exists'],
 'candidateOwnerExistsInRealWorkspace':workspace['files']['infra/security/summary-v2/owner.mjs']['exists'],
 'sameResultConsumedByGateSummaryPromotion':'NOT_TESTED_NOT_INSTALLED',
 'productionOwnerAdded':False,'parallelOwnerInvented':False,
 'stopReason':'An unchanged frozen adapter already violates original Gate semantics under IO latency. Cannot wire it as production authority without changing/revalidating the adapter.'})
write('active-contract-state.json',{'producer':{'path':'infra/security/security-summary.mjs','sha256':active['files']['infra/security/security-summary.mjs']['sha256'],'schema':1},
 'realJenkinsRevision':live['scmBranches'],'realLibrary':active['libraries'],
 'activeManagerSha256':active['files']['vars/securityManager.groovy']['sha256'],
 'localFrozenManagerSha256':sha(root/'vars/securityManager.groovy'),
 'managerIdentitiesAreDifferent':active['files']['vars/securityManager.groovy']['sha256']!=sha(root/'vars/securityManager.groovy'),
 'differenceScope':'Local generic module switches/readiness and optional provenance selection differ from active pinned library; no identity conflation or deployment was performed.',
 'activeVersionedPolicyContracts':'ABSENT from inspected real workspace; do not mislabel local frozen compatibility locks as already installed runtime integrity Gates',
 'localFrozenContractsUnchanged':['infra/security/policy/versions/promotion-baseline-v1.json','infra/security/policy/versions/regression-baseline-v1.json'],
 'candidateContract':'CANDIDATE_ONLY_NOT_IN_PRODUCTION',
 'v1ActiveNow':True,'v2WasActivated':False,'v1RestoredAfterRollback':False,'rollbackReason':'NO_SWITCH_PERFORMED; original V1 stayed active. No V2->V1 runtime rollback proof is claimed.',
 'activeRollbackIdentity':'Existing job SCM and library pin 9a78cc89f22fa98fb1ffcc43e2ae279299471793 plus active-v1-tree exact bytes; do not substitute the different local Manager snapshot.'})
oldtests=load(root/'evidence/2026-11-02/summary-v2-migration/final-validation.json')['tests']
write('test-disposition.json',{'currentControlledPreflight':{'sourceCodeBodyExecuted':True,'cases':4,'matches':2,'drifts':2,'gateProcessExit':2,
 'classification':clock['classification'],'realPipelineExecution':False,'sourceInputsPreserved':True},
 'previousIterationOnly':oldtests,
 'currentPolicyCore':'NOT_RERUN_AFTER_STOP; previous 5/5 retained',
 'currentOriginalRegression':'NOT_RERUN_AFTER_STOP; previous 147/147 retained',
 'currentConsumerRegressions':'NOT_RUN_AFTER_COMPATIBILITY_STOP',
 'previousSamplesNotOverwritten':True,
 'historicalCompatibilityDisposition':'Existing 2128 matching samples remain valid for their specific inputs. They cannot establish general runtime compatibility after these two new counterexamples.'})
write('verdict.json',{'REAL_V2_PIPELINE_INTEGRATION':'FAILED','SUMMARY_V2_MIGRATION':'FAILED',
 'meaning':'Compatibility acceptance preflight FAILED. Real V2 pipeline was NOT started; original production V1 has not regressed or been changed by this work.',
 'blocker':clock['blocker'],'affectedSources':['falco-baseline','falco-final'],
 'evidenceClass':clock['classification'],'minimalFix':clock['requiredAction'],
 'preexistingB1':'OPEN; real runtime capture not implemented','preexistingB2':'OPEN; real single authoritative owner not installed','preexistingB3':'OPEN; actual consumers not migrated',
 'newCompatibilityBlocker':'Confirmed FAIL->PASS in unchanged frozen Falco adapter for delayed two-window sampling; requires explicit source compatibility revalidation before integration.',
 'artifactComplete':False,'realSummaryV2Generated':False,'runtimeDifferential':'NOT_EXECUTED',
 'runtimeAntiSelfApproval':'NOT_TESTED','runtimeRollback':'NOT_TESTED_NOT_SWITCHED',
 'release':0,'rollout':0,'stopped':True})
report=root/'docs/REAL-V2-PIPELINE-INTEGRATION-20261102.md'
if report.exists():
    items=re.findall(r'^(\d+)\. ',report.read_text(),re.M)
    assert [int(i) for i in items]==list(range(1,42))
selected=[p for p in base.rglob('*') if p.is_file() and p.name!='artifact-sha256.json']
if report.exists(): selected.append(report)
write('artifact-sha256.json',{str(p.relative_to(root)):sha(p) for p in sorted(selected)})
print(json.dumps({'verdict':'FAILED','existingChanged':len(changed),'hashReferences':len(references),'hashFailures':len(reference_errors),'controls':2,'FAIL_to_PASS_counterexamples':len(drifts),'productionChanged':False,'release':0,'rollout':0}))
