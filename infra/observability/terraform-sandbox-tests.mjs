import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const files=Object.fromEntries(['sandbox','worker','test_sandbox','test_worker','test_build_inputs'].map(n=>[n,fs.readFileSync('infra/devops-lab/iac/isolated/'+n+'.py','utf8')]));
files.build_input_extractor=fs.readFileSync('infra/devops-lab/iac/isolated/security/extract.py','utf8');
const script=`import json,sys,types,unittest,tempfile,pathlib
files=json.load(sys.stdin)
root=tempfile.TemporaryDirectory();base=pathlib.Path(root.name);(base/"security").mkdir();(base/"security/extract.py").write_text(files.pop("build_input_extractor"))
for name,source in files.items():
 m=types.ModuleType(name);m.__file__=str(base/(name+'.py'));sys.modules[name]=m;exec(compile(source,name+'.py','exec'),m.__dict__)
suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[n]) for n in ['test_sandbox','test_worker','test_build_inputs'])
r=unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(not r.wasSuccessful())`;
const r=spawnSync('docker',['run','--rm','--network','none','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges','--user','65532:65532','--memory','128m','--cpus','0.5','--pids-limit','32','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','-i','python@sha256:fbecd461fc72d21b2143c6eaba25143738079154a6d0ea3da3aec724f50eed4a','python','-B','-c',script],{input:JSON.stringify(files),encoding:'utf8',timeout:60000,maxBuffer:1024*1024});
process.stdout.write(r.stdout??'');process.stderr.write(r.stderr??'');if(r.status!==0||r.error)throw Error('Isolated Python policy tests failed: '+(r.error?.message??r.status));
