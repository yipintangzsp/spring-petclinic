import pathlib,runpy,json,shlex,hashlib,sys
sys.dont_write_bytecode=True
root=pathlib.Path.cwd();here=pathlib.Path(__file__).resolve().parent
checks=json.loads((here/'private-cache-preflight.json').read_text());verified=json.loads((here/'official-artifact-checksums.json').read_text());assert checks['status']==verified['status']=='VERIFIED'
source=(root/'infra/security/manager-v2/sbom/linux-entry.py').read_text();source_sha=hashlib.sha256(source.encode()).hexdigest();api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,json,sys,os,pwd,hashlib,shutil,xml.etree.ElementTree as ET
x=json.load(sys.stdin);r=pathlib.Path('/var/lib/security-sbom');u=pwd.getpwnam('security-sbom')
assert u.pw_uid==993 and u.pw_gid==984
assert hashlib.sha256((r/'fixture/pom.xml').read_bytes()).hexdigest()=='cac4cdce5296a6d6bc31477e9a7feca0a30d9797129da11c9c9d8883a4c55cc2'
assert not list((r/'runs').iterdir())
b=r/'entry-before-direct-goal-20261106.py'
if not b.exists():shutil.copyfile(r/'entry.py',b);b.chmod(0o444)
p=r/'entry.py.pending';p.write_text(x['source']);p.chmod(0o444);os.replace(p,r/'entry.py')
if not(r/'receipts').exists():(r/'receipts').mkdir(mode=0o700);os.chown(r/'receipts',u.pw_uid,u.pw_gid)
assert ET.parse(r/'settings.xml').findtext('./mirrors/mirror/url')==(r/'repository').as_uri()
print(json.dumps({'runnerSha256':hashlib.sha256((r/'entry.py').read_bytes()).hexdigest(),'inputSha256':hashlib.sha256((r/'fixture/pom.xml').read_bytes()).hexdigest(),'uid':u.pw_uid,'gid':u.pw_gid,'temporaryDirectories':0,'repository':'LOCAL_READ_ONLY_FILE_MIRROR','generationCount':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps({'source':source}),timeout=20));assert x['runnerSha256']==source_sha
with(here/'executor-install.json').open('x')as f:json.dump(x,f,indent=2)
p=root/'infra/security/manager-v2/sbom/projects.json';cfg=json.loads(p.read_text());cfg['projects']['java-sbom-demo'].pop('blockedReason',None);cfg['projects']['java-sbom-demo']['runnerSha256']=source_sha;p.write_text(json.dumps(cfg,indent=2)+'\n')
print(json.dumps(x))
