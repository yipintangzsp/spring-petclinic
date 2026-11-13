"""Run existing candidate checks in a disposable tree; preserve all old evidence."""
from pathlib import Path
import json,subprocess,tempfile,shutil
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='security-v2-r2-') as temp:
    root=Path(temp)/'repo';shutil.copytree(O/'v1-tree',root)
    # Only the disposable test checkout uses the r2 contract at the old default
    # fixture path. The real old candidate remains unchanged and inactive.
    shutil.copy2(R/'infra/security/summary-v2/candidate-integrity-r2.json',root/'infra/security/summary-v2/candidate-integrity.json')
    base=O/'controlled-candidate-tests';base.mkdir(exist_ok=False)
    (base/'v1-tree').symlink_to(O/'v1-tree',target_is_directory=True)
    destination=root/'evidence/2026-11-02/summary-v2-migration';destination.parent.mkdir(parents=True,exist_ok=True);destination.symlink_to(base,target_is_directory=True)
    command=['node','--test','infra/security/summary-v2/handoff.test.mjs','infra/security/summary-v2/compatibility.test.mjs']
    with (O/'rebased-candidate-tests.log').open('w') as out,(O/'rebased-candidate-tests.stderr').open('w') as err:
        p=subprocess.run(command,cwd=root,stdout=out,stderr=err)
    (O/'rebased-candidate-command.json').write_text(json.dumps({'command':command,'exitStatus':p.returncode,'classification':'CONTROLLED_CANDIDATE_TESTS_NOT_REAL_PIPELINE','disposableCheckout':True,'originalTestsChanged':False,'oldEvidenceModified':False,'temporaryTreeCleaned':True},indent=2)+'\n')
    print(json.dumps({'exitStatus':p.returncode,'classification':'CONTROLLED_CANDIDATE_TESTS_NOT_REAL_PIPELINE'}))
    if p.returncode:raise SystemExit(p.returncode)
