from pathlib import Path
import tempfile,shutil,subprocess,json,sys
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-final-four';source=sys.argv[1];assert source in ['gitleaks','command']
with tempfile.TemporaryDirectory(prefix='runtime-six-frozen-tests-') as temp:
 root=Path(temp)/'repo';shutil.copytree(O/'v1-tree',root,symlinks=False)
 # Read-only existing frozen files are copied; test-generated fixture/differential
 # outputs stay in this disposable tree, never mutate accepted evidence.
 for d in ['infra/security','resources/security-manager']:
  shutil.copytree(R/d,root/d,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__'))
 for f in ['Jenkinsfile','Jenkinsfile.security-audit']:shutil.copy2(R/f,root/f)
 for d in ['evidence/2026-11-01/gitleaks-parent','evidence/2026-11-01/command-parent','evidence/2026-11-01/policy-engine']:
  if (R/d).exists():shutil.copytree(R/d,root/d,dirs_exist_ok=True)
 command=['node','--test','infra/security/policy/'+source+'-parent.test.mjs']
 with (O/(source+'-frozen-parent-tests.log')).open('w') as log:p=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 (O/(source+'-frozen-parent-test-execution.json')).write_text(json.dumps({'exitStatus':p.returncode,'command':command,'classification':'FROZEN_DIFFERENTIAL_RECHECK_IN_DISPOSABLE_TREE','oldEvidenceModified':False,'tempTreeRemovedAtExit':True},indent=2)+'\n')
 if p.returncode:raise SystemExit(p.returncode)
print('FROZEN_PARENT_SOURCE_TESTS_PASS '+source)
