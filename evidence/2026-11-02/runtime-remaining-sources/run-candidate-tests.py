"""Run unchanged candidate tests in a disposable checkout, preserving old evidence."""
from pathlib import Path
import json,subprocess,tempfile,shutil
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='runtime-facts-candidate-') as temp:
    root=Path(temp)/'repo';shutil.copytree(O/'v1-tree',root)
    shutil.copy2(R/'infra/security/summary-v2/candidate-integrity-r2.json',root/'infra/security/summary-v2/candidate-integrity.json')
    base=O/'controlled-candidate-tests';base.mkdir(exist_ok=False)
    (base/'v1-tree').symlink_to(O/'v1-tree',target_is_directory=True)
    dest=root/'evidence/2026-11-02/summary-v2-migration';dest.parent.mkdir(parents=True,exist_ok=True);dest.symlink_to(base,target_is_directory=True)
    command=['node','--test','infra/security/summary-v2/handoff.test.mjs','infra/security/summary-v2/compatibility.test.mjs']
    with (O/'candidate-tests.log').open('w') as out,(O/'candidate-tests.stderr').open('w') as err:
        p=subprocess.run(command,cwd=root,stdout=out,stderr=err)
    receipt={'command':command,'exitStatus':p.returncode,'classification':'CONTROLLED_CANDIDATE_TESTS_NOT_REAL_RUNTIME','disposableCheckout':True,'temporaryCheckoutRemoved':True,'oldEvidenceModified':False}
    (O/'candidate-test-execution.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
    if p.returncode:raise SystemExit(p.returncode)
