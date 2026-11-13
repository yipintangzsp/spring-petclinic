import runpy,shlex,pathlib,json,sys
sys.dont_write_bytecode=True
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,subprocess,json,tempfile,os,pwd,shutil,hashlib,signal
r=pathlib.Path('/var/lib/security-sbom');u=pwd.getpwnam('security-sbom');w=pathlib.Path(tempfile.mkdtemp(prefix='project-b-check-',dir=r/'runs'));os.chown(w,u.pw_uid,u.pw_gid);b=(r/'fixtures/java-sbom-demo-b/pom.xml').read_bytes();(w/'pom.xml').write_bytes(b);os.chown(w/'pom.xml',u.pw_uid,u.pw_gid)
base=['runuser','-u','security-sbom','--','env','-i','PATH=/usr/bin:/bin','JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64','HOME='+str(w),'TMPDIR='+str(w),'MAVEN_OPTS=-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=1','nice','-n','10',str(r/'maven/bin/mvn'),'-B','-ntp','-s',str(r/'settings.xml'),'-Dmaven.repo.local='+str(w/'repository')];checks=[]
try:
 for args in [['-Dmaven.main.skip=true','org.apache.maven.plugins:maven-compiler-plugin:3.15.0:compile'],['-Dcyclonedx.skip=true','org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom']]:
  p=subprocess.Popen(base+args,cwd=w,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
  try:out=p.communicate(timeout=30)[0]
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);out=p.communicate(timeout=5)[0]
  checks.append({'goal':args[-1],'exitCode':p.returncode,'logSha256':hashlib.sha256(out).hexdigest()});assert not list(w.rglob('*.cdx.json'))
finally:shutil.rmtree(w)
m=int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')));load=os.getloadavg()[0];free=shutil.disk_usage(r/'runs').free
print(json.dumps({'projectId':'java-sbom-demo-b','inputSha256':hashlib.sha256(b).hexdigest(),'checks':checks,'admitted':all(c['exitCode']==0 for c in checks)and m>=2097152 and load<=4.5 and free>=2147483648,'resources':{'memKiB':m,'load1':load,'freeBytes':free},'generationInvocations':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=80));print(json.dumps(x));p=pathlib.Path('evidence/2026-11-06/sbom-second-project/preflight.json');p.write_text(json.dumps(x,indent=2))
