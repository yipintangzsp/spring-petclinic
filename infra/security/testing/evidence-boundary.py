"""macOS test runner boundary. Children may write ONLY one new temporary tree.

No test may run with the source repository as cwd. This is an actual sandbox,
not a promise based on grep or a checksum after a destructive test has run.
"""
from pathlib import Path
import json,os,subprocess,sys,tempfile,stat,hashlib
ROOT=Path(__file__).resolve().parents[3]
def snapshot(files):
 out={}
 for n in files:
  p=ROOT/n;s=p.lstat();out[n]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()}
 return out
def validate_tree(tree):
 tree=Path(tree);assert tree==tree.resolve() and tree.is_dir() and not tree.is_relative_to(ROOT),'Test tree must be real, temporary and outside source repository'
 assert tree.parent==Path(tempfile.gettempdir()).resolve() and tree.name.startswith('security-cosign-boundary-'),'Unowned test tree'
 for p in tree.rglob('*'):
  assert not p.is_symlink(),'Test input symlink escape'
  if p.is_file():assert p.stat().st_nlink==1,'Hard-linked test input'
 return tree
def sandbox_command(tree,args):
 tree=validate_tree(tree);literal=json.dumps(str(tree));profile='(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (subpath '+literal+'))(allow file-write* (literal "/dev/null"))'
 return ['/usr/bin/sandbox-exec','-p',profile,*args]
def guarded(tree,args,timeout=120):
 tree=validate_tree(tree);tmp=tree/'tmp';tmp.mkdir(exist_ok=True)
 env={'PATH':os.environ['PATH'],'HOME':str(tree),'TMPDIR':str(tmp),'PYTHONDONTWRITEBYTECODE':'1','LANG':'C'}
 return subprocess.run(sandbox_command(tree,args),cwd=tree,env=env,text=True,capture_output=True,timeout=timeout)
def preflight(out):
 out=Path(out).resolve();assert out.is_relative_to(ROOT/'evidence/2026-11-05/security-manager-v2-cosign-real')
 protected=out/'boundary-canary.txt';protected.write_text('OWNED CURRENT ROUND BOUNDARY CANARY\n');before=protected.stat();original=protected.read_bytes()
 with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
  tree=Path(d).resolve();history=tree/'read-only-history';history.mkdir();(history/'old.json').write_text('{"synthetic":true}')
  # Writable clone evidence is disposable; the original repository is read-only.
  code='''import os,json,pathlib,socket
p=pathlib.Path(CANARY);results={}
for kind,fn in [('overwrite',lambda:p.write_text('bad')),('unlink',lambda:p.unlink()),('chmod',lambda:p.chmod(0o666)),('mkdir',lambda:(p.parent/'UNAUTHORIZED_TEST_DIRECTORY').mkdir())]:
 try:fn();results[kind]='ALLOWED'
 except PermissionError:results[kind]='DENIED'
(pathlib.Path.cwd()/'allowed-output.json').write_text('{"fixture":true}')
print(json.dumps(results))
'''
  p=guarded(tree,[sys.executable,'-B','-c','CANARY='+repr(str(protected))+'\n'+code]);assert p.returncode==0,p.stderr
  checks=json.loads(p.stdout);assert all(x=='DENIED' for x in checks.values()),checks
  assert (tree/'allowed-output.json').is_file()
  rejected=False
  try:sandbox_command(ROOT,['true'])
  except AssertionError:rejected=True
  assert rejected
 assert protected.read_bytes()==original and protected.stat().st_mtime_ns==before.st_mtime_ns and protected.stat().st_mode==before.st_mode
 return {'classification':'REAL_OS_SANDBOX_PREFLIGHT_ONLY','backend':'macOS sandbox-exec','denied':checks,'disposableTreeWrite':'ALLOWED','repositoryCwdRejected':True,'network':'DENIED_BY_PROFILE_NOT_NETWORK_TEST','canaryContentAndMtimeModeUnchanged':True,'temporaryTreeRemoved':not Path(d).exists(),'historicalWriteProbes':0,'historicalDeleteProbes':0}
if __name__=='__main__':print(json.dumps(preflight(sys.argv[1])))
