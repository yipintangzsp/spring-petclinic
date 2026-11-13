from pathlib import Path
import tempfile,shutil,subprocess,json,sys
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-final-four';source=sys.argv[1];assert source in ['trivy','cosign','zap','dojo']
with tempfile.TemporaryDirectory(prefix='runtime-four-frozen-tests-') as temp:
 root=Path(temp)/'repo';shutil.copytree(O/'v1-tree',root,symlinks=False)
 for d in ['infra/security','resources/security-manager']:shutil.copytree(R/d,root/d,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__'))
 for f in ['Jenkinsfile','Jenkinsfile.security-audit']:shutil.copy2(R/f,root/f)
 # Existing tests write only under their accepted evidence locations IN THIS
 # DISPOSABLE COPY. None of the original sealed evidence is mutated.
 for directory in ['evidence/2026-11-01/policy-engine','evidence/2026-11-01/remaining-policy','evidence/2026-11-01/'+source+'-parent','evidence/2026-11-02/trivy-db','evidence/2026-11-01/dojo-parent']:
  if (R/directory).exists():shutil.copytree(R/directory,root/directory,dirs_exist_ok=True)
 cmd=['node','--test','infra/security/policy/'+source+'-parent.test.mjs']
 with (O/(source+'-source-tests.log')).open('w') as out:p=subprocess.run(cmd,cwd=root,stdout=out,stderr=subprocess.STDOUT)
 (O/(source+'-source-tests-execution.json')).write_text(json.dumps({'command':cmd,'exitStatus':p.returncode,'scope':'FROZEN_LOGIC_DIFFERENTIAL_RECHECK_NOT_NEW_LIVE_RUNTIME','disposableTree':True,'originalEvidenceModified':False},indent=2)+'\n')
 if p.returncode:raise SystemExit(p.returncode)
 print('SOURCE_TESTS_PASS '+source)
