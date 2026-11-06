"""Fixed offline generator. Dedicated UID; no user paths/options/environment."""
import os,sys,json,pathlib,hashlib,subprocess,tempfile,resource,signal,time,base64,zipfile,shutil,re
ROOT=pathlib.Path('/var/lib/security-sbom');OUT=ROOT/'runs';sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
 cmd=os.environ.get('SSH_ORIGINAL_COMMAND','').split()
 if len(cmd)!=3 or cmd[0]!='generate-v1' or cmd[1]!='java-sbom-demo' or not re.fullmatch(r'web-[a-f0-9-]{36}',cmd[2]):raise RuntimeError('FIXED_COMMAND_ONLY')
 if os.getuid()==0 or set(os.getgroups())!={os.getgid()}:raise RuntimeError('UNTRUSTED_IDENTITY')
 for p in ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml']:
  if os.access(p,os.R_OK):raise RuntimeError('PRODUCTION_AUTHORITY_READABLE')
 mem=int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')))
 if mem<2*1024*1024 or os.getloadavg()[0]>4.5 or shutil.disk_usage(OUT).free<2*1024**3:raise RuntimeError('LINUX_RESOURCE_BUDGET_BLOCKED')
 plugin=ROOT/'repository/org/cyclonedx/cyclonedx-maven-plugin/2.9.3/cyclonedx-maven-plugin-2.9.3.jar'
 if sha(plugin.read_bytes())!='c452d5eebe28bc86bef2e7c72d129f04f60877bef843eac8120f01fb655be293':raise RuntimeError('TOOL_SHA_MISMATCH')
 pom=(ROOT/'fixture/pom.xml').read_bytes();expected=json.loads((ROOT/'approval.json').read_text())
 if sha(pom)!=expected['sourceArtifactSha256']:raise RuntimeError('INPUT_SHA_MISMATCH')
 if len(list(OUT.iterdir()))>=10:raise RuntimeError('RUN_BUDGET_EXHAUSTED')
 started=time.time();work=pathlib.Path(tempfile.mkdtemp(prefix=cmd[2]+'-',dir=OUT));os.chmod(work,0o700)
 p=None
 try:
  (work/'pom.xml').write_bytes(pom)
  env={'PATH':'/usr/bin:/bin','HOME':str(work),'TMPDIR':str(work),'LANG':'C','JAVA_HOME':'/usr/lib/jvm/java-21-openjdk-arm64','MAVEN_OPTS':'-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ReservedCodeCacheSize=64m -XX:ActiveProcessorCount=1 -Djava.io.tmpdir='+str(work)}
  argv=[str(ROOT/'maven/bin/mvn'),'-o','-B','-ntp','-s',str(ROOT/'settings.xml'),'-Dmaven.repo.local='+str(ROOT/'repository'),'-DskipTests','package']
  def limits():
   os.nice(10);resource.setrlimit(resource.RLIMIT_CPU,(45,45));resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024**2,8*1024**2));resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
  log=open(work/'command.log','wb');p=subprocess.Popen(argv,cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
  try:rc=p.wait(timeout=25)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=3);raise RuntimeError('GENERATOR_TIMEOUT')
  finally:log.close()
  if rc:raise RuntimeError('GENERATOR_EXIT_'+str(rc))
  raw=(work/'target/classes/META-INF/sbom/application.cdx.json').read_bytes()
  with zipfile.ZipFile(work/'target/java-dependencies-demo-1.0.0.jar')as z:packaged=z.read('META-INF/sbom/application.cdx.json')
  if raw!=packaged or len(raw)>1024*1024:raise RuntimeError('PACKAGED_SBOM_MISMATCH')
  bom=json.loads(raw)
  if bom.get('bomFormat')!='CycloneDX' or bom.get('specVersion')!='1.6' or len(bom.get('components',[]))<10:raise RuntimeError('SBOM_INVALID')
  (work/'sbom.json').write_bytes(raw);(work/'sbom-summary.json').write_text(json.dumps({'sha256':sha(raw),'components':len(bom['components'])}))
  print(json.dumps({'kind':'RestrictedLinuxSbom','projectId':cmd[1],'runId':cmd[2],'sourceArtifactSha256':sha(pom),'toolVersion':'2.9.3','toolSha256':sha(plugin.read_bytes()),'startedAtMs':int(started*1000),'completedAtMs':int(time.time()*1000),'exitCode':rc,'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'noNewPrivs':'NoNewPrivs:\t1'in pathlib.Path('/proc/self/status').read_text(),'dockerReadable':False,'kubeconfigReadable':False,'sbomBase64':base64.b64encode(raw).decode(),'packagedBase64':base64.b64encode(packaged).decode(),'sbomSha256':sha(raw),'componentCount':len(bom['components']),'inputKind':'FIXED_NONPRODUCTION_POM','scope':'APPLICATION_MAVEN_DEPENDENCIES_ONLY','generationCount':1,'logSha256':sha((work/'command.log').read_bytes())}))
 except RuntimeError as e:
  # Fixed error codes only, no command output or dependency URLs/credentials.
  print(json.dumps({'error':str(e)}));raise
 finally:
  if p and p.poll()is None:
   try:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=3)
   except ProcessLookupError:pass
  shutil.rmtree(work)
try:main()
except BaseException:sys.exit(1)
