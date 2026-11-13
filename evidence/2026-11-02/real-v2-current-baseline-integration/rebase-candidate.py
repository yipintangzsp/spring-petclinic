"""Create an exact, inactive r2 contract. Never rewrite old or active contracts."""
from pathlib import Path
import json,hashlib
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def create(p,x):
    with p.open('x') as f:f.write(json.dumps(x,indent=2,sort_keys=True)+'\n')
old=read(R/'infra/security/summary-v2/candidate-integrity.json')
v1=read(O/'V1_IDENTITY.json');readiness=read(R/'evidence/2026-11-02/summary-integration-readiness-recheck/readiness.json')
assert readiness['SUMMARY_INTEGRATION_READINESS']=='READY' and readiness['parentStageAggregate']['drifts']==0
repair=read(R/'evidence/2026-11-02/falco-time-contract-repair/evidence-supersession.json')
transitions={x['path']:x for x in repair['sourceTransitions']}
for version,contract in old['versions'].items():
    for name,h in contract['files'].items():
        current=sha(R/name)
        if current!=h:
            t=transitions[name]
            assert h==t['oldSha256']==sha(R/t['archivedOldPath']) and current==t['newSha256']
# Candidate-side V1 rollback selection accepts the current frozen checkout's
# exact V1 source set. The active production Promotion/Regression locks stay intact.
v1files={n:v1['files'][n]['sha256'] for n in old['versions']['V1']['files']}
files={str(p.relative_to(R)):sha(p) for p in sorted((R/'infra/security/summary-v2').glob('*.mjs')) if not p.name.endswith('.test.mjs') and p.name!='fixture-harness.mjs'}
files.update({n:x['sha256'] for n,x in v1['files'].items() if n.startswith('infra/security/policy/')})
producer=old['versions']['V2']['producer']
assert producer['sha256']==files['infra/security/summary-v2/producer.mjs']
new={'schema':1,'revision':'r2-current-falco-observed-clock','activation':'CANDIDATE_ONLY_NOT_IN_PRODUCTION','selection':'explicit trusted version; no fallback',
 'compatibilityBaseline':{'readiness':'evidence/2026-11-02/summary-integration-readiness-recheck/readiness.json','readinessSha256':sha(R/'evidence/2026-11-02/summary-integration-readiness-recheck/readiness.json'),'parentSamples':2202,'drift':0,'falcoBaseline':89,'falcoFinal':91,'policyVersion':'baseline-v1'},
 'versions':{'V1':{**old['versions']['V1'],'producer':{'identity':v1['identity'],'sha256':v1['producerSha256']},'files':v1files},'V2':{**old['versions']['V2'],'producer':producer,'files':files}}}
target=R/'infra/security/summary-v2/candidate-integrity-r2.json';create(target,new)
create(O/'V2_REBASED_IDENTITY.json',{'producer':producer,'candidateRevision':new['revision'],'contractPath':str(target.relative_to(R)),'contractSha256':sha(target),'previousContractSha256':sha(R/'infra/security/summary-v2/candidate-integrity.json'),'productionActivation':False,'currentV1RollbackIdentity':v1['identity'],'currentV1RollbackTreeSha256':v1['snapshotTreeSha256'],'acceptedAuthoritativeBaseline':new['compatibilityBaseline'],'activeIntegrityContractChanged':False,'previousCandidateRetained':True,'changedReferences':[{'version':v,'path':n,'old':h,'new':new['versions'][v]['files'].get(n)} for v,c in old['versions'].items() for n,h in c['files'].items() if new['versions'][v]['files'].get(n)!=h],'addedReferences':{v:sorted(set(c['files'])-set(old['versions'][v]['files'])) for v,c in new['versions'].items()}})
print(json.dumps({'candidateRevision':new['revision'],'contractSha256':sha(target),'V1FileCount':len(v1files),'V2FileCount':len(files),'activeV1Modified':False}))
