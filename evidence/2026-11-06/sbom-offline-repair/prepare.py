import pathlib,runpy,json,shlex,sys
sys.dont_write_bytecode=True
here=pathlib.Path(__file__).resolve().parent
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,subprocess,json,os,pwd,shutil,hashlib,urllib.request,concurrent.futures,datetime,re,signal
root=pathlib.Path('/var/lib/security-sbom');prep=root/'prepare-20261106';u=pwd.getpwnam('security-sbom');expected='cac4cdce5296a6d6bc31477e9a7feca0a30d9797129da11c9c9d8883a4c55cc2'
assert not prep.exists();assert hashlib.sha256((root/'fixture/pom.xml').read_bytes()).hexdigest()==expected
assert int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')))>=2*1024*1024 and os.getloadavg()[0]<=4.5 and shutil.disk_usage(root).free>3*1024**3
prep.mkdir(mode=0o700);os.chown(prep,u.pw_uid,u.pw_gid);repo=prep/'repository';shutil.copytree(root/'repository',repo)
work=prep/'work';work.mkdir();(work/'pom.xml').write_bytes((root/'fixture/pom.xml').read_bytes())
settings=prep/'settings.xml';settings.write_text('<settings><interactiveMode>false</interactiveMode><mirrors><mirror><id>central</id><mirrorOf>*</mirrorOf><url>https://repo.maven.apache.org/maven2</url></mirror></mirrors><profiles><profile><id>strict</id><repositories><repository><id>central</id><url>https://repo.maven.apache.org/maven2</url><releases><checksumPolicy>fail</checksumPolicy></releases><snapshots><enabled>false</enabled></snapshots></repository></repositories><pluginRepositories><pluginRepository><id>central</id><url>https://repo.maven.apache.org/maven2</url><releases><checksumPolicy>fail</checksumPolicy></releases><snapshots><enabled>false</enabled></snapshots></pluginRepository></pluginRepositories></profile></profiles><activeProfiles><activeProfile>strict</activeProfile></activeProfiles></settings>')
before={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest()for p in repo.rglob('*')if p.is_file()and p.suffix in ['.jar','.pom']}
for p in prep.rglob('*'):
 os.chown(p,u.pw_uid,u.pw_gid);p.chmod(0o700 if p.is_dir()else 0o600)
env={'PATH':'/usr/bin:/bin','JAVA_HOME':'/usr/lib/jvm/java-21-openjdk-arm64','HOME':str(prep),'TMPDIR':str(work),'LANG':'C','MAVEN_OPTS':'-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=1 -Djava.io.tmpdir='+str(work)}
cmd=['/usr/sbin/runuser','-u','security-sbom','--','/usr/bin/env','-i']+[k+'='+v for k,v in env.items()]+['/usr/bin/nice','-n','10',str(root/'maven/bin/mvn'),'-B','-ntp','-s',str(settings),'-Dmaven.repo.local='+str(repo),'org.apache.maven.plugins:maven-dependency-plugin:3.11.0:go-offline']
checks=[]
for offline in [False,True]:
 c=cmd.copy()
 if offline:c.insert(-1,'-o')
 log=prep/('offline.log'if offline else'online.log')
 with log.open('wb')as out:
  p=subprocess.Popen(c,cwd=work,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
  try:rc=p.wait(timeout=180 if not offline else 60)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=5);rc=124
 text=log.read_text(errors='replace');checks.append({'mode':'OFFLINE_RESOLUTION'if offline else'ONLINE_PREPARATION','exitCode':rc,'logSha256':hashlib.sha256(log.read_bytes()).hexdigest(),'bytes':log.stat().st_size,'fixedGoal':'maven-dependency-plugin:3.11.0:go-offline','generatedSbomFiles':len(list(work.rglob('*.cdx.json'))),'errorCoordinates':sorted(set(re.findall(r'org\.[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:(?:jar|pom):[A-Za-z0-9_.-]+',text)))[:30] if rc else []})
 if rc:break
assert not list(work.rglob('*.cdx.json')),'UNEXPECTED_GENERATION'
changed=[p for p in repo.rglob('*')if p.is_file()and p.suffix in ['.jar','.pom']and before.get(str(p.relative_to(repo)))!=hashlib.sha256(p.read_bytes()).hexdigest()]
def verify(p):
 relative=str(p.relative_to(repo));b=p.read_bytes();sidecar=p.with_name(p.name+'.sha1');assert sidecar.exists(),'MISSING_CHECKSUM '+relative
 local=sidecar.read_text().strip().split()[0];assert hashlib.sha1(b).hexdigest()==local,'CHECKSUM_MISMATCH '+relative
 # Fresh official HTTPS checksum; no repository authentication.
 with urllib.request.urlopen('https://repo.maven.apache.org/maven2/'+relative+'.sha1',timeout=12)as resp:official=resp.read(200).decode().strip().split()[0]
 assert local==official,'ORIGIN_CHECKSUM_MISMATCH '+relative
 return {'path':relative,'sha256':hashlib.sha256(b).hexdigest(),'officialSha1':official,'source':'https://repo.maven.apache.org/maven2/','bytes':len(b)}
verified=[]
if len(checks)==2 and all(c['exitCode']==0 for c in checks):
 with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:verified=list(pool.map(verify,changed))
 # Publish only missing verified immutable artifacts. Never overwrite existing artifacts.
 copied=0
 for p in repo.rglob('*'):
  if not p.is_file():continue
  rel=p.relative_to(repo);target=root/'repository'/rel
  if p.name.endswith(('.lastUpdated','.lock','.tmp')):continue
  if target.exists():
   if p.suffix in ['.jar','.pom']:assert target.read_bytes()==p.read_bytes(),'EXISTING_ARTIFACT_CHANGE '+str(rel)
   continue
  target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target);target.chmod(0o444);copied+=1
 for d in (root/'repository').rglob('*'):
  if d.is_dir():d.chmod(0o555)
else:copied=0
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sourceArtifactSha256':expected,'identity':{'uid':u.pw_uid,'gid':u.pw_gid},'checks':checks,'newArtifacts':verified,'publishedFileCount':copied,'generationCount':0,'credentialsUsed':False,'status':'VERIFIED'if copied and len(checks)==2 and all(c['exitCode']==0 for c in checks)else'INCOMPLETE'}
# Preparation is disposable; diagnostics retain hashes/exit codes, not unrestricted logs.
shutil.rmtree(prep)
print(json.dumps(result))
'''
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=390))
with(here/'dependency-preparation.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps({'status':x['status'],'checks':x['checks'],'verifiedNewArtifactCount':len(x['newArtifacts']),'publishedFileCount':x['publishedFileCount'],'generationCount':0}))
