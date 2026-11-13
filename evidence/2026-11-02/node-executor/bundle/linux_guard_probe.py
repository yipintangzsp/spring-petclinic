from pathlib import Path
import sys,json,subprocess,unittest,platform,os,hashlib
from dataclasses import replace
from unittest.mock import patch
sys.path.insert(0,'/fixture/harness')
import test_sops_preparation as t
# Explicitly authorized unit identity. No fake credential sent to an API.
case=t.Setup();case.setUp()
try:
 work=Path('/fixture/work');p=replace(case.profile,allowed_cwds=(work,))
 node=Path('/fixture/runtime/bin/node')
 sanity=unittest.TestSuite(t.PortableGuardTests(x) for x in ['test_missing_profile','test_unknown_profile','test_wrong_config_digest','test_admin_credential_rejected_by_min','test_proxy_rejects_changed_snapshot'])
 test=unittest.TextTestRunner(verbosity=1).run(sanity);assert test.wasSuccessful()
 with patch.object(t.g,'verify_live') as identity_transport:
  inline="require('fs').writeFileSync('/fixture/results/inline.json',JSON.stringify({version:process.version,arch:process.arch,platform:process.platform,nodePath:process.execPath,cwd:process.cwd()}))"
  inline_result=t.g.execute(str(p.binding.path),case.env,profile=p,mode='child',child_command=[str(node),'-e',inline],child_cwd=work)
  preflight=json.loads(Path('/fixture/results/inline.json').read_text());assert preflight['version']=='v22.23.3' and preflight['arch']=='arm64' and preflight['platform']=='linux'
  result=t.g.execute(str(p.binding.path),case.env,profile=p,mode='child',child_command=[str(node),'--experimental-vm-modules','/fixture/startup.mjs'],child_cwd=work)
 assert identity_transport.call_count==2
 env={'HOME':'/fixture/empty-home','PATH':'/fixture/runtime/bin:/usr/bin:/bin','LANG':'C.UTF-8'}
 versions={}
 for name,cmd in [('node',[str(node),'--version']),('npm',[str(node),'/fixture/runtime/lib/node_modules/npm/bin/npm-cli.js','--version'])]:
  r=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=20);assert r.returncode==0;versions[name]=r.stdout.strip()
 obj={'inlineSentinel':{'guard':inline_result,'result':preflight},'machine':platform.machine(),'uname':platform.uname()._asdict(),'versions':versions,'nodeBinarySha256':hashlib.sha256(node.read_bytes()).hexdigest(),'guard':result,'guardSanity':{'tests':test.testsRun,'failures':len(test.failures),'errors':len(test.errors)},'identityValidation':'SYNTHETIC_UNIT_TRANSPORT_ONLY_USER_APPROVED','realMinRbacAuthentication':'NOT_TESTED_NO_SERVICEACCOUNT_EXISTS','credentialsMounted':False,'productionApiAccess':0}
 Path('/fixture/results/guard-integration.json').write_text(json.dumps(obj,indent=2))
 print(json.dumps({'startup':json.loads(Path('/fixture/results/startup.json').read_text()),'integration':obj}))
finally:case.doCleanups()
