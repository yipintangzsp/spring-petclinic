from pathlib import Path
import json,subprocess,tempfile,shutil
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-final-four'
with tempfile.TemporaryDirectory(prefix='runtime-four-completeness-') as temp:
 root=Path(temp)/'repo';shutil.copytree(O/'v1-tree',root)
 shutil.copy2(R/'infra/security/summary-v2/candidate-integrity-r2.json',root/'infra/security/summary-v2/candidate-integrity.json')
 (root/'infra/security/runtime-facts').mkdir(exist_ok=True);shutil.copy2(R/'infra/security/runtime-facts/completeness-negative.test.mjs',root/'infra/security/runtime-facts/completeness-negative.test.mjs')
 base=O/'controlled-completeness-tests';base.mkdir(exist_ok=False);(base/'v1-tree').symlink_to(O/'v1-tree',target_is_directory=True)
 dest=root/'evidence/2026-11-02/summary-v2-migration';dest.parent.mkdir(parents=True,exist_ok=True);dest.symlink_to(base,target_is_directory=True)
 with (O/'completeness-negative.log').open('w') as out:p=subprocess.run(['node','--test','infra/security/runtime-facts/completeness-negative.test.mjs'],cwd=root,stdout=out,stderr=subprocess.STDOUT)
 (O/'completeness-test-execution.json').write_text(json.dumps({'exitStatus':p.returncode,'classification':'SYNTHETIC_UNIT_ONLY_NEGATIVE_COMPLETENESS_NOT_LIVE_ARTIFACT','realCompleteArtifactGenerated':False,'disposableCheckoutRemoved':True},indent=2)+'\n')
 if p.returncode:raise SystemExit(p.returncode)
 print('COMPLETENESS_NEGATIVE_TESTS_PASS')
