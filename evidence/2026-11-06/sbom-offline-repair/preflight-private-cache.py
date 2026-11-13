import pathlib,runpy,shlex,json,sys
sys.dont_write_bytecode=True
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,json,subprocess,pwd,os,tempfile,shutil,hashlib,re,signal,zipfile,xml.etree.ElementTree as ET
r=pathlib.Path('/var/lib/security-sbom');u=pwd.getpwnam('security-sbom');settings=r/'settings.xml';backup=r/'settings-before-local-mirror-20261106.xml'
if not backup.exists():shutil.copyfile(settings,backup);backup.chmod(0o444)
settings.chmod(0o644);settings.write_text('<settings><interactiveMode>false</interactiveMode><mirrors><mirror><id>central</id><mirrorOf>*</mirrorOf><url>file:///var/lib/security-sbom/repository</url></mirror></mirrors></settings>');settings.chmod(0o444)
w=pathlib.Path(tempfile.mkdtemp(prefix='local-resolution-',dir=r/'runs'));os.chown(w,u.pw_uid,u.pw_gid);(w/'pom.xml').write_bytes((r/'fixture/pom.xml').read_bytes());os.chown(w/'pom.xml',u.pw_uid,u.pw_gid)
base=['runuser','-u','security-sbom','--','env','-i','PATH=/usr/bin:/bin','JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64','HOME='+str(w),'TMPDIR='+str(w),'MAVEN_OPTS=-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=1 -Djava.net.preferIPv4Stack=true','nice','-n','10',str(r/'maven/bin/mvn'),'-B','-ntp','-s',str(settings),'-Dmaven.repo.local='+str(w/'repository')]
checks=[]
try:
 for name,args in [('PROJECT_DEPENDENCY_RESOLUTION_COMPILE_SKIPPED',['-Dmaven.main.skip=true','org.apache.maven.plugins:maven-compiler-plugin:3.15.0:compile']),('CYCLONEDX_CLASS_REALM_GENERATION_SKIPPED',['-Dcyclonedx.skip=true','org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom'])]:
  p=subprocess.Popen(base+args,cwd=w,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
  try:b=p.communicate(timeout=30)[0]
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);b=p.communicate(timeout=5)[0]
  text=b.decode(errors='replace');assert not list(w.rglob('*.cdx.json'))
  checks.append({'mode':name,'exitCode':p.returncode,'logSha256':hashlib.sha256(b).hexdigest(),'logBytes':len(b),'skipMessages':[l for l in text.splitlines()if 'skip'in l.lower()and l.startswith('[INFO]')][:3],'diagnostic':[re.sub(r'(?:https?|file)://\S+','[REPOSITORY_URL]',l)for l in text.splitlines()if l.startswith('[ERROR]')][:18],'generationCount':0})
 result={'resolvedArtifacts':[{'path':str(p.relative_to(w/'repository')),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in (w/'repository').rglob('*')if p.is_file()and p.suffix in ['.jar','.pom']],'checks':checks,'sourceArtifactSha256':hashlib.sha256((w/'pom.xml').read_bytes()).hexdigest(),'repositorySource':'LOCAL_FILE_MIRROR_ONLY','productionCacheModified':False,'generationCount':0,'status':'VERIFIED'if all(c['exitCode']==0 for c in checks)else'INCOMPLETE'}
finally:shutil.rmtree(w)
print(json.dumps(result))
'''
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=80))
with pathlib.Path('evidence/2026-11-06/sbom-offline-repair/private-cache-preflight.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
