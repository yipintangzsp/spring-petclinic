"""Create-only Falco time repair baseline. No execution or production access."""
import collections
import hashlib
import json
import pathlib
import shutil

root=pathlib.Path(__file__).resolve().parents[3]
out=root/'evidence/2026-11-02/falco-time-contract-repair'
if out.exists():
    raise SystemExit('Refusing to overwrite Falco repair baseline')
out.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
before={}
for directory in ['infra','resources','vars','docs','evidence','k8s']:
    for p in (root/directory).rglob('*'):
        if p.is_file() and not p.is_symlink() and out not in p.parents:
            before[str(p.relative_to(root))]=sha(p)
for p in root.glob('Jenkinsfile*'):
    if p.is_file():before[str(p.relative_to(root))]=sha(p)
write=lambda n,d:(out/n).write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
write('before-sha256.json',before)
paths=['infra/security/runtime/health.mjs','infra/security/runtime/event-policy.mjs',
       'infra/security/runtime/health-contract.mjs','infra/security/policy/falco-parent.mjs',
       'infra/security/policy/falco-parent.test.mjs','infra/security/policy/engine.mjs',
       'infra/security/policy/versions/baseline-v1.json','infra/security/policy/versions/falco-parent-baseline-v1.json']
hashes={}
for relative in paths:
    p=root/relative;dest=out/'before'/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest);hashes[relative]=sha(p)
old=root/'evidence/2026-11-01/falco-parent/differential.json'
rows=json.loads(old.read_text())['records']
counts={mode:{'cases':len([r for r in rows if r['mode']==mode]),
              'oldDecisions':dict(collections.Counter(r['oldDecision'] for r in rows if r['mode']==mode)),
              'standardDecisions':dict(collections.Counter(r['standardDecision'] for r in rows if r['mode']==mode))}
        for mode in ['baseline','check']}
assert counts['baseline']['cases']==52 and counts['check']['cases']==54
write('FALCO_BEFORE_IDENTITY.json',{'productionBaselineGate':hashes[paths[0]],'productionFinalGate':hashes[paths[0]],
      'files':hashes,'counts':counts,'oldDifferentialPath':str(old.relative_to(root)),'oldDifferentialSha256':sha(old),
      'adapterRollbackTarget':'before/infra/security/policy/falco-parent.mjs',
      'scope':'Frozen code and controlled compatibility samples, not production sensor certification'})
write('current-status.json',{'falco-baseline':'REVALIDATION_REQUIRED','falco-final':'REVALIDATION_REQUIRED',
      'SUMMARY_INTEGRATION_READINESS':'SUSPENDED','SUMMARY_V2_MIGRATION':'INCOMPLETE',
      'REAL_V2_PIPELINE_INTEGRATION':'BLOCKED_BY_CONFIRMED_DRIFT',
      'historicalEvidence':'Preserved; not authoritative for missing time-boundary coverage',
      'gateChanged':False,'baselineChanged':False,'release':0,'rollout':0})
print(json.dumps({'protectedFiles':len(before),'oldAdapterSha256':hashes['infra/security/policy/falco-parent.mjs'],'baseline':counts['baseline'],'final':counts['check']}))
