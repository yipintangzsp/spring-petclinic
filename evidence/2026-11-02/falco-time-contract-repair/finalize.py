"""Targeted Falco acceptance only; does not run the 18-source readiness audit."""
import collections
import hashlib
import json
import pathlib
import re

out=pathlib.Path(__file__).resolve().parent
root=out.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
load=lambda p:json.loads(p.read_text())
def write(name,value):
    (out/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')

identity=load(out/'FALCO_BEFORE_IDENTITY.json')
before=load(out/'before-sha256.json')
allowed={'infra/security/policy/falco-parent.mjs','infra/security/policy/falco-parent.test.mjs'}
changed=[p for p,h in before.items() if not (root/p).is_file() or sha(root/p)!=h]
assert set(changed)==allowed,changed
for p,h in identity['files'].items():
    assert sha(out/'before'/p)==h
    if p not in allowed: assert sha(root/p)==h
prior=load(root/'evidence/2026-11-01/falco-parent/differential.json')['records']
parent=load(out/'differential.json')['records']
key=lambda r:(r['mode'],r['name'],r['branch'])
assert [key(r) for r in parent]==[key(r) for r in prior]
assert all((a['oldDecision'],a['standardDecision'])==(b['oldDecision'],b['standardDecision']) for a,b in zip(parent,prior))
assert all(r['oldDecision']==r['standardDecision'] and r['rawPreserved'] for r in parent)
timing_before=load(out/'timing-before.json')
timing_after=load(out/'timing-after.json')
assert timing_before['samples']==timing_after['samples']==74
assert timing_before['drift']==20 and timing_after['drift']==0
assert [(r['mode'],r['name'],r['inputSha256']) for r in timing_before['records']]==[(r['mode'],r['name'],r['inputSha256']) for r in timing_after['records']]
assert all(r['match'] and r['assessmentEqual'] and r['rawPreserved'] for r in timing_after['records'])
for old,new in zip(timing_before['records'],timing_after['records']):
    if old['originalDiscoveryCase']:
        assert (old['oldDecision'],old['standardDecision'])==('FAIL','PASS')
        assert (new['oldDecision'],new['standardDecision'])==('FAIL','FAIL')
    path=out/new['fixture']
    assert hashlib.sha256(json.dumps(load(path),separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==new['inputSha256']

tests={}
for name,filename,count in [('completeFalcoParent','parent-tests.log',107),('timingEvidenceGuards','timing-guards.log',12),('policyCore','policy-core.log',5)]:
    text=(out/filename).read_text();stats={k:int(v) for k,v in re.findall(r'^ℹ (tests|pass|fail|cancelled|skipped|todo) (\d+)$',text,re.M)}
    assert stats['tests']==stats['pass']==count and stats['fail']==stats['cancelled']==stats['skipped']==stats['todo']==0
    tests[name]={**stats,'log':filename,'exitStatus':0}
write('test-command-exits.json',{'timingBefore':{'command':'node evidence/2026-11-02/falco-time-contract-repair/timing-matrix.mjs before','exitStatus':0,'meaning':'Expected drift reproduced, not an acceptance PASS','drift':20},
 'timingAfter':{'command':'node evidence/2026-11-02/falco-time-contract-repair/timing-matrix.mjs after','exitStatus':0,'drift':0},'nodeTests':tests})

counts={}
for mode,previous_count in [('baseline',52),('check',54)]:
    old=[r for r in parent if r['mode']==mode];new=[r for r in timing_after['records'] if r['mode']==mode];allrows=old+new
    assert len(old)==previous_count and len(new)==37
    counts[mode]={'previousCases':len(old),'addedTimingCases':len(new),'total':len(allrows),'MATCH':len(allrows),'DRIFT':0,
      'oldDecisions':dict(collections.Counter(r['oldDecision'] for r in allrows)),
      'standardDecisions':dict(collections.Counter(r['standardDecision'] for r in allrows))}
    assert counts[mode]['oldDecisions']==counts[mode]['standardDecisions']
branches=collections.Counter(r['branch'] for r in parent)
write('continuity-check.json',{'status':'VERIFIED_FOR_CONTROLLED_FROZEN_STAGE',
 'previousCasesPreservedByNameBranchAndDecision':106,'branches':dict(branches),
 'sameSharedSamplingCodeForBothModes':True,'differentSetupPreserved':'baseline identity establishment vs final baseline/source/build/container/boot/restart continuity',
 'historicalWarningsStillInformational':True,'thresholdsAndFailRulesChanged':False,'newTimingAssessmentsMatchOriginal':True,
 'guardTests':12,'realSensorCertification':False})

refs=load(root/'evidence/2026-11-02/summary-integration-readiness-audit/source-integrity.json')['checks']
failures=[{'path':r['path'],'lock':r['lock']} for r in refs if sha(root/r['path'])!=r['expected']]
assert not failures
candidate=load(root/'infra/security/summary-v2/candidate-integrity.json')
stale=[p for p,h in candidate['versions']['V2']['files'].items() if sha(root/p)!=h]
assert set(stale)==allowed,stale
write('source-preservation.json',{'previousProtectedFiles':len(before),'changedPreexistingFiles':changed,'unexpectedChangedFiles':[],
 'productionGateModified':False,'productionGateBefore':identity['productionBaselineGate'],'productionGateAfter':sha(root/'infra/security/runtime/health.mjs'),
 'adapterBefore':identity['files']['infra/security/policy/falco-parent.mjs'],'adapterAfter':sha(root/'infra/security/policy/falco-parent.mjs'),
 'policyBaselineModified':False,'policyEngineModified':False,'policyBaselineSha256':sha(root/'infra/security/policy/versions/baseline-v1.json'),
 'summaryProducerModified':False,'promotionModified':False,'regressionModified':False,
 'authoritativeHashReferences':len(refs),'authoritativeDistinctFiles':len({r['path'] for r in refs}),'authoritativeHashFailures':failures,
 'acceptedIntegrityContractsChanged':False,
 'inactiveV2Candidate':'NOT_ACTIVATABLE: exact hashes intentionally left unchanged; repair now requires next readiness/version reconciliation',
 'inactiveCandidateStaleFiles':stale,'full18SourceAuditRun':False,
 'productionApiCalls':0,'productionBuilds':0,'release':0,'rollout':0})

superseded=[{'path':'evidence/2026-11-01/falco-parent','status':'SUPERSEDED_FOR_TIME_BOUNDARY_COVERAGE','retained':True,
 'reason':'Original 52/54 accepted cases remain valid, but zero-time-IO evidence does not cover actual per-sample wall-clock latency'},
 {'path':'evidence/2026-11-02/real-v2-pipeline-integration/falco-clock-preflight.json','status':'HISTORICAL_DEFECT_REPRODUCTION_RETAINED','retained':True}]
transitions=[]
for name in sorted(allowed):
    transitions.append({'path':name,'oldSha256':identity['files'][name],'newSha256':sha(root/name),
      'archivedOldPath':str((out/'before'/name).relative_to(root)),
      'archivedOldSha256':sha(out/'before'/name),
      'reason':'Observed per-sample time contract repair' if name.endswith('falco-parent.mjs') else 'Accepted fixtures gain explicit zero-IO clock facts and verify query clock; output redirected to new evidence; all 106 case identities preserved'})
write('evidence-supersession.json',{'historicalEvidence':superseded,'sourceTransitions':transitions,
 'oldEvidenceOverwritten':False,'newAuthority':str(out.relative_to(root)),
 'scope':'Falco only; not a replacement for the 18-source aggregate audit'})

matrix=[]
for mode,source in [('baseline','falco-baseline'),('check','falco-final')]:
    matrix.append({'source':source,'adapterStatus':'VERIFIED','finalStatus':'VERIFIED',
      'scope':'Controlled complete frozen parent-stage logic including observed wall-clock bounds, not live business incident proof',
      'productionEntry':'node infra/security/runtime/health.mjs'+(' baseline' if mode=='baseline' else ''),
      'productionSourceSha256':sha(root/'infra/security/runtime/health.mjs'),
      'classifierAdapterPath':'infra/security/policy/falco-parent.mjs','adapterSha256':sha(root/'infra/security/policy/falco-parent.mjs'),
      'policyEngineSha256':sha(root/'infra/security/policy/engine.mjs'),'policyBaselineSha256':sha(root/'infra/security/policy/versions/baseline-v1.json'),
      **counts[mode],'rawFactsPreserved':True,'evidenceFiles':['differential.json','timing-before.json','timing-after.json','timing-evidence-guards.json'],
      'historicalNaturalNegative':'DEFERRED_REAL_NEGATIVE_EVIDENCE','productionExecutions':0})
write('authoritative-falco-matrix.json',{'scope':'FALCO_ONLY_TARGETED_REVALIDATION','sources':matrix,'aggregateReadiness':'SUSPENDED_PENDING_AUTHORITATIVE_RECHECK'})
write('acceptance.json',{'FALCO_TIME_CONTRACT':'VERIFIED','FALCO_COMPATIBILITY':'VERIFIED','scope':'Complete controlled frozen Falco baseline/final parent-stage compatibility with explicit observed windows',
 'beforeDrift':20,'afterDrift':0,'timingSamples':74,'baseline':counts['baseline'],'final':counts['check'],
 'allDifferentialSamples':180,'MATCH':180,'DRIFT':0,'rawFactsPreserved':True,'nodeTests':tests,
 'productionGateChanged':False,'policyBaselineChanged':False,'adapterChanged':True,'productionBuilds':0,'release':0,'rollout':0,
 'remainingBlocker':None,'remainingScopeLimit':'Controlled source-logic compatibility, not live pipeline integration or sensor certification',
 'nextPermittedPhase':'AUTHORITATIVE SUMMARY_INTEGRATION_READINESS RECHECK; do not resume Summary V2 now'})
if not (out/'initial-status.json').exists():
    (out/'initial-status.json').write_bytes((out/'current-status.json').read_bytes())
write('current-status.json',{'falco-baseline':'VERIFIED','falco-final':'VERIFIED','scope':'Controlled frozen stage time-boundary compatibility',
 'FALCO_TIME_CONTRACT':'VERIFIED','FALCO_COMPATIBILITY':'VERIFIED','SUMMARY_INTEGRATION_READINESS':'SUSPENDED',
 'SUMMARY_V2_MIGRATION':'INCOMPLETE','REAL_V2_PIPELINE_INTEGRATION':'NOT_RESUMED',
 'reason':'Targeted Falco revalidation is complete. Incorporating new adapter/evidence into the authoritative 18-source readiness is a separate next phase.',
 'summaryV2Resumed':False,'productionBuilds':0,'release':0,'rollout':0})
report=root/'docs/FALCO-TIME-CONTRACT-20261102.md'
if report.exists():
    items=re.findall(r'^(\d+)\. ',report.read_text(),re.M)
    assert [int(i) for i in items]==list(range(1,33))
files=[p for p in out.rglob('*') if p.is_file() and p.name!='artifact-sha256.json']
files.extend([root/'infra/security/policy/falco-parent.mjs',root/'infra/security/policy/falco-parent.test.mjs',root/'infra/security/policy/falco-time-contract.test.mjs',root/'infra/security/testing/freeze-falco-time.py'])
if report.exists():files.append(report)
write('artifact-sha256.json',{str(p.relative_to(root)):sha(p) for p in sorted(files)})
print(json.dumps({'FALCO_TIME_CONTRACT':'VERIFIED','FALCO_COMPATIBILITY':'VERIFIED','baseline':counts['baseline'],'final':counts['check'],'timing':74,'DRIFT':0,'existingHashRefs':len(refs),'unexpectedChanged':0,'readiness':'SUSPENDED','release':0,'rollout':0}))
