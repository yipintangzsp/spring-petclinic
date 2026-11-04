from pathlib import Path
import sys,importlib.util,tempfile,shutil,json
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];spec=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b);base=json.loads((O/'protected-before.json').read_text());assert b.snapshot(base['protected'])==base['protected']
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
 tree=Path(d).resolve();target=tree/'verification';target.mkdir()
 for folder in ['installed-dojo-parser','samples']:shutil.copytree(O/folder,target/folder)
 for file in ['installed-parser-inspection.json','verify-parser.py']:shutil.copyfile(O/file,target/file)
 p=b.guarded(tree,[sys.executable,'-B',str(target/'verify-parser.py')],timeout=30)
 with(O/'parser-isolated.log').open('x')as f:f.write(p.stdout+p.stderr)
 assert p.returncode==0,p.stderr
 value=json.loads((target/'parser-compatibility.json').read_text());value['executionBoundary']='REAL_OS_SANDBOX_UNIQUE_TEMPORARY_TREE'
assert b.snapshot(base['protected'])==base['protected'];value['temporaryTreeRemoved']=not Path(d).exists()
with(O/'parser-compatibility-isolated.json').open('x')as f:json.dump(value,f,indent=2);f.write('\n')
print(json.dumps({'payloads':len(value['checks']),'negativeChecks':len(value['negativeChecks']),'temporaryTreeRemoved':value['temporaryTreeRemoved'],'remoteImport':'NOT_TESTED'}))
