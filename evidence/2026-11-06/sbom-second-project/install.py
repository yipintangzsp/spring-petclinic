import pathlib,runpy,shlex,json,hashlib,sys
sys.dont_write_bytecode=True
root=pathlib.Path.cwd();here=pathlib.Path(__file__).resolve().parent;projects=json.loads((root/'infra/security/manager-v2/sbom/projects.json').read_text());source=(root/'infra/security/manager-v2/sbom/linux-entry.py').read_text();runnerSha=hashlib.sha256(source.encode()).hexdigest()
known=json.loads((root/'evidence/2026-11-06/sbom-offline-repair/official-artifact-checksums.json').read_text());assert known['status']=='VERIFIED'
payload={'catalog':{p:{'fixturePath':c['fixturePath'],'sourceArtifactSha256':c['sourceArtifactSha256']}for p,c in projects['projects'].items()},'source':source,'pomB':(root/'infra/security/manager-v2/sbom/project-b-pom.xml').read_text(),'known':known['artifacts']}
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,json,sys,pwd,os,hashlib,shutil
x=json.load(sys.stdin);r=pathlib.Path('/var/lib/security-sbom');u=pwd.getpwnam('security-sbom');assert u.pw_uid==993 and u.pw_gid==984
assert not list((r/'runs').iterdir())
assert hashlib.sha256((r/'fixture/pom.xml').read_bytes()).hexdigest()==x['catalog']['java-sbom-demo']['sourceArtifactSha256']
for item in x['known']:
 assert hashlib.sha256((r/'repository'/item['path']).read_bytes()).hexdigest()==item['sha256'],'VERIFIED_CACHE_CHANGED'
b=r/'entry-before-two-projects-20261107.py'
if not b.exists():shutil.copyfile(r/'entry.py',b);b.chmod(0o444)
p=r/x['catalog']['java-sbom-demo-b']['fixturePath'];assert not p.exists();p.parent.mkdir(parents=True);p.write_text(x['pomB']);p.chmod(0o444);p.parent.chmod(0o555)
c=r/'project-catalog.json';assert not c.exists();c.write_text(json.dumps(x['catalog']));c.chmod(0o444)
p=r/'entry.py.next';p.write_text(x['source']);p.chmod(0o444);os.replace(p,r/'entry.py')
print(json.dumps({'runnerSha256':hashlib.sha256((r/'entry.py').read_bytes()).hexdigest(),'identity':{'uid':u.pw_uid,'gid':u.pw_gid},'projects':x['catalog'],'cacheMatches159VerifiedArtifacts':True}))
'''
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(payload),timeout=30));assert x['runnerSha256']==runnerSha
for p in projects['projects'].values():p['runnerSha256']=runnerSha
(root/'infra/security/manager-v2/sbom/projects.json').write_text(json.dumps(projects,indent=2)+'\n')
with(here/'installation.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
