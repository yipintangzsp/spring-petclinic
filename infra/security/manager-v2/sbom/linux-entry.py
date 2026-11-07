"""Fixed offline generator; one passive approved POM, no caller paths or options."""
import os,sys,json,pathlib,hashlib,subprocess,tempfile,resource,signal,time,base64,zipfile,shutil,re,xml.etree.ElementTree as ET
ROOT=pathlib.Path('/var/lib/security-sbom');OUT=ROOT/'runs';RECEIPTS=ROOT/'receipts'
sha=lambda b:hashlib.sha256(b).hexdigest()
TOOL_SHA='c452d5eebe28bc86bef2e7c72d129f04f60877bef843eac8120f01fb655be293'
def atomic_receipt(run_id,value):
 data=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 tmp=RECEIPTS/(run_id+'.tmp');final=RECEIPTS/(run_id+'.json')
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
 try:
  with os.fdopen(fd,'wb')as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.link(tmp,final) # Atomic and exclusive: never overwrite an earlier receipt.
 finally:tmp.unlink(missing_ok=True)
 return sha(data)
def main():
 cmd=os.environ.get('SSH_ORIGINAL_COMMAND','').split()
 catalog=json.loads((ROOT/'project-catalog.json').read_text())
 if len(cmd)!=3 or cmd[0]!='generate-v1' or cmd[1]not in catalog or not re.fullmatch(r'web-[a-f0-9-]{36}',cmd[2]):raise RuntimeError('FIXED_COMMAND_ONLY')
 run_id=cmd[2];started=time.time();work=None;p=None;packet=None
 receipt={'schemaVersion':1,'kind':'RestrictedLinuxSbomReceipt','projectId':cmd[1],'runId':run_id,'uid':os.getuid(),'gid':os.getgid(),'toolVersion':'2.9.3','runnerSha256':sha(pathlib.Path(__file__).read_bytes()),'startedAtMs':int(started*1000),'exitCode':None,'stage':'PREREQUISITE','goal':'org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom','repositoryMode':'LOCAL_FILE_MIRROR_PRIVATE_RUN_CACHE','error':None,'logSha256':None,'logBytes':0,'missingCoordinates':[],'generationInvocations':0,'cleanup':'NOT_VERIFIED'}
 try:
  if os.getuid()==0 or set(os.getgroups())!={os.getgid()}:raise RuntimeError('UNTRUSTED_IDENTITY')
  for path in ['/run/docker.sock','/etc/rancher/k3s/k3s.yaml']:
   if os.access(path,os.R_OK):raise RuntimeError('PRODUCTION_AUTHORITY_READABLE')
  mem=int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')))
  receipt['resourceBudget']={'memAvailableKiB':mem,'load1':os.getloadavg()[0],'freeBytes':shutil.disk_usage(OUT).free}
  if mem<2*1024*1024 or receipt['resourceBudget']['load1']>4.5 or receipt['resourceBudget']['freeBytes']<2*1024**3:raise RuntimeError('LINUX_RESOURCE_BUDGET_BLOCKED')
  mirrors=ET.parse(ROOT/'settings.xml').findall('./mirrors/mirror')
  if len(mirrors)!=1 or mirrors[0].findtext('mirrorOf')!='*' or mirrors[0].findtext('url')!=(ROOT/'repository').as_uri():raise RuntimeError('REPOSITORY_SOURCE_NOT_LOCAL')
  plugin=ROOT/'repository/org/cyclonedx/cyclonedx-maven-plugin/2.9.3/cyclonedx-maven-plugin-2.9.3.jar'
  if sha(plugin.read_bytes())!=TOOL_SHA:raise RuntimeError('TOOL_SHA_MISMATCH')
  expected=catalog[cmd[1]];relative=pathlib.PurePosixPath(expected['fixturePath'])
  if relative.is_absolute()or '..'in relative.parts:raise RuntimeError('INPUT_PATH_REJECTED')
  source=ROOT.joinpath(relative)
  if source.is_symlink()or source.resolve()!=source or not source.is_relative_to(ROOT):raise RuntimeError('INPUT_PATH_REJECTED')
  st=source.stat()
  if st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('INPUT_OWNERSHIP_REJECTED')
  pom=source.read_bytes()
  if sha(pom)!=expected['sourceArtifactSha256']:raise RuntimeError('INPUT_SHA_MISMATCH')
  receipt['sourceArtifactSha256']=sha(pom)
  if len(list(OUT.iterdir()))>=10 or len(list(RECEIPTS.iterdir()))>=50:raise RuntimeError('RUN_BUDGET_EXHAUSTED')
  work=pathlib.Path(tempfile.mkdtemp(prefix=run_id+'-',dir=OUT));os.chmod(work,0o700);(work/'pom.xml').write_bytes(pom)
  env={'PATH':'/usr/bin:/bin','HOME':str(work),'TMPDIR':str(work),'LANG':'C','JAVA_HOME':'/usr/lib/jvm/java-21-openjdk-arm64','MAVEN_OPTS':'-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ReservedCodeCacheSize=64m -XX:ActiveProcessorCount=1 -Djava.io.tmpdir='+str(work)}
  argv=[str(ROOT/'maven/bin/mvn'),'-B','-ntp','-s',str(ROOT/'settings.xml'),'-Dmaven.repo.local='+str(work/'repository'),'org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom']
  def limits():
   os.nice(10);resource.setrlimit(resource.RLIMIT_CPU,(45,45));resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024**2,8*1024**2));resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
  receipt['stage']='GENERATOR';receipt['generationInvocations']=1;receipt['processStartedAtMs']=int(time.time()*1000)
  with (work/'command.log').open('xb')as log:
   p=subprocess.Popen(argv,cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
   try:receipt['exitCode']=p.wait(timeout=25)
   except subprocess.TimeoutExpired:raise RuntimeError('GENERATOR_TIMEOUT')
  receipt['processCompletedAtMs']=int(time.time()*1000)
  if receipt['exitCode']!=0:raise RuntimeError('GENERATOR_EXIT_ERROR')
  receipt['stage']='COLLECTION';raw=(work/'target/classes/META-INF/sbom/application.cdx.json').read_bytes()
  # This evidence container packages the generated bytes only; it is not an application build.
  with zipfile.ZipFile(work/'sbom-evidence.jar','x')as z:z.writestr('META-INF/sbom/application.cdx.json',raw)
  with zipfile.ZipFile(work/'sbom-evidence.jar')as z:packaged=z.read('META-INF/sbom/application.cdx.json')
  if raw!=packaged or len(raw)>1024*1024:raise RuntimeError('PACKAGED_SBOM_MISMATCH')
  bom=json.loads(raw)
  if bom.get('bomFormat')!='CycloneDX' or bom.get('specVersion')!='1.6' or len(bom.get('components',[]))<10:raise RuntimeError('SBOM_INVALID')
  (work/'sbom.json').write_bytes(raw);(work/'sbom-summary.json').write_text(json.dumps({'sha256':sha(raw),'components':len(bom['components'])}))
  packet={'kind':'RestrictedLinuxSbom','projectId':cmd[1],'runId':run_id,'sourceArtifactSha256':sha(pom),'toolVersion':'2.9.3','toolSha256':TOOL_SHA,'startedAtMs':int(started*1000),'completedAtMs':int(time.time()*1000),'exitCode':receipt['exitCode'],'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'noNewPrivs':'NoNewPrivs:\t1'in pathlib.Path('/proc/self/status').read_text(),'dockerReadable':False,'kubeconfigReadable':False,'sbomBase64':base64.b64encode(raw).decode(),'packagedBase64':base64.b64encode(packaged).decode(),'sbomSha256':sha(raw),'componentCount':len(bom['components']),'inputKind':'FIXED_NONPRODUCTION_POM','scope':'APPLICATION_MAVEN_DEPENDENCIES_ONLY','generationCount':1,'packaging':'SBOM_EVIDENCE_CONTAINER_NOT_APPLICATION_JAR'}
  receipt['stage']='COMPLETED';receipt['sbomSha256']=sha(raw);receipt['componentCount']=len(bom['components'])
 except BaseException as e:
  receipt['error']=str(e)if isinstance(e,RuntimeError)and re.fullmatch('[A-Z_]+',str(e))else'SBOM_EXECUTION_ERROR';packet=None
 finally:
  try:
   if p:
    # Kill only the private session if any member remains after the Maven parent.
    try:os.killpg(p.pid,0);os.killpg(p.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    if p.poll()is None:
     try:p.wait(timeout=2)
     except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=2)
    receipt['exitCode']=p.returncode
    try:os.killpg(p.pid,0);raise RuntimeError('DESCENDANT_CLEANUP_FAILED')
    except ProcessLookupError:pass
   if work:
    log=work/'command.log'
    if log.exists():
     data=log.read_bytes();receipt['logSha256']=sha(data);receipt['logBytes']=len(data)
     # Coordinates only; no URLs, raw output, environment or credentials leave the host.
     if receipt['error']:receipt['missingCoordinates']=sorted(set(re.findall(r'[A-Za-z][A-Za-z0-9_.-]*:[A-Za-z0-9_.-]+:(?:jar|pom):[0-9][A-Za-z0-9_.-]*',data.decode(errors='replace'))))[:20]
    shutil.rmtree(work)
   receipt['cleanup']='VERIFIED'
  except BaseException:receipt['cleanup']='INCOMPLETE';receipt['error']='CLEANUP_FAILED';packet=None
  receipt['completedAtMs']=int(time.time()*1000)
 receipt_hash=atomic_receipt(run_id,receipt)
 print(json.dumps({**(packet or {'error':receipt['error'] or 'SBOM_EXECUTION_ERROR'}),'diagnostic':receipt,'diagnosticSha256':receipt_hash}),flush=True)
 return 0 if packet and receipt['cleanup']=='VERIFIED'else 1
try:sys.exit(main())
except BaseException as e:
 if isinstance(e,SystemExit):raise
 print(json.dumps({'error':'SBOM_PREREQUISITE_OR_RECEIPT_ERROR'}),flush=True);sys.exit(1)
