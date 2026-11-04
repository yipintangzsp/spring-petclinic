"""Execute only the explicitly user-approved, hash-receipted fixture package."""
import hashlib,json,pathlib,shlex,subprocess,tarfile
OUT=pathlib.Path(__file__).resolve().parent;ROOT=OUT.parents[2]
receipt=json.loads((OUT/'linux-transfer-receipt.json').read_text())
archive=OUT/'linux-fixtures-final.tar'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==receipt['archiveSha256']
for name,digest in receipt['files'].items():
    assert hashlib.sha256((ROOT/'infra/observability'/name).read_bytes()).hexdigest()==digest
remote="""import sys,tarfile,tempfile,pathlib,subprocess,shutil,json
work=pathlib.Path(tempfile.mkdtemp(prefix='trivy-guard-boundary-fixtures-'))
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
 for item in archive:
  p=pathlib.PurePosixPath(item.name)
  if p.is_absolute() or '..' in p.parts or not item.isfile():raise RuntimeError('UNSAFE_FIXTURE_ARCHIVE')
  target=work/item.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(item).read())
p=subprocess.run(['python3','-B',str(work/'run.py')],capture_output=True,text=True,timeout=180)
if p.returncode:print(json.dumps({'exit':p.returncode,'error':p.stderr,'workPreserved':str(work)}))
else:
 result=json.loads(p.stdout);safe=all(s['exit']==0 for s in result['suites'])
 if safe:shutil.rmtree(work)
 result['fixtureDirectoryRemoved']=safe;result['retainedPath']=None if safe else str(work);print(json.dumps(result))
"""
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes',
 '-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58','python3 -c '+shlex.quote(remote)]
for name in ['linux-execution.stdout','linux-execution.stderr','linux-execution.json',
 'guard-linux.log','path-races-linux.log','evidence-protection-linux.log','legacy-guard-linux.log']:
    assert not (OUT/name).exists(),'Refuse overwriting existing execution evidence'
r=subprocess.run(ssh,input=archive.read_bytes(),capture_output=True,timeout=220)
(OUT/'linux-execution.stdout').write_bytes(r.stdout);(OUT/'linux-execution.stderr').write_bytes(r.stderr)
result=json.loads(r.stdout)
for s in result.get('suites',[]):(OUT/(s['name']+'.log')).write_text(s.pop('log'))
(OUT/'linux-execution.json').write_text(json.dumps({'sshExit':r.returncode,'hostKeyVerification':'STRICT_UNCHANGED',
 'userApprovedTransfer':True,'archiveSha256':receipt['archiveSha256'],**result},indent=2)+'\n')
print(json.dumps({'sshExit':r.returncode,'suites':[(s['name'],s['exit']) for s in result.get('suites',[])],
 'fixturesRemoved':result.get('fixtureDirectoryRemoved'),'retainedPath':result.get('retainedPath')}))
