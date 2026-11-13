import runpy,shlex,json,pathlib,sys
sys.dont_write_bytecode=True
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,json,subprocess,pwd,os,tempfile,shutil,hashlib,re,signal
r=pathlib.Path('/var/lib/security-sbom');u=pwd.getpwnam('security-sbom');w=pathlib.Path(tempfile.mkdtemp(prefix='dependency-check-',dir=r/'runs'));os.chown(w,u.pw_uid,u.pw_gid)
(w/'pom.xml').write_bytes((r/'fixture/pom.xml').read_bytes());os.chown(w/'pom.xml',u.pw_uid,u.pw_gid)
cmd=['runuser','-u','security-sbom','--','env','-i','PATH=/usr/bin:/bin','JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64','HOME='+str(w),'TMPDIR='+str(w),'MAVEN_OPTS=-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=1 -Djava.net.preferIPv4Stack=true','nice','-n','10',str(r/'maven/bin/mvn'),'-o','-B','-ntp','-s',str(r/'settings.xml'),'-Dmaven.repo.local='+str(r/'repository'),'-Dcyclonedx.skip=true','org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom']
try:
 p=subprocess.Popen(cmd,cwd=w,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
 try:b=p.communicate(timeout=30)[0]
 except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGTERM);b=p.communicate(timeout=5)[0]
 text=b.decode(errors='replace');generated=list(w.rglob('*.cdx.json'));assert not generated
 # The fixed POM/settings contain no credentials. Only bounded sanitized diagnostics are exported.
 errors=[re.sub(r'https?://\S+','[REPOSITORY_URL]',l)for l in text.splitlines()if l.startswith('[ERROR]')][:12]
 x={'mode':'OFFLINE_CYCLONEDX_LOADER_EXPLICIT_SKIP','exitCode':p.returncode,'logSha256':hashlib.sha256(b).hexdigest(),'logBytes':len(b),'skipConfirmed':'Skipping CycloneDX'in text or 'CycloneDX: Skipping'in text or 'Skipping CycloneDX goal'in text,'diagnostic':errors,'inputSha256':hashlib.sha256((w/'pom.xml').read_bytes()).hexdigest(),'generationCount':0}
finally:shutil.rmtree(w)
print(json.dumps(x))
'''
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=45))
with pathlib.Path('evidence/2026-11-06/sbom-offline-repair/native-loader-preflight.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
