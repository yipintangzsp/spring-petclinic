import runpy,pathlib,json,shlex,subprocess,base64,sys,hashlib
sys.dont_write_bytecode=True
ROOT=pathlib.Path('/Users/zhangsir/code/petclinic-platform-20261011');HERE=pathlib.Path(__file__).resolve().parent
api=runpy.run_path(str(ROOT/'evidence/2026-11-05/security-manager-v2-loki/inspect-production.py'))
key=pathlib.Path.home()/'.ssh/security-manager-v2-sbom'
if not key.exists():
 p=subprocess.run(['ssh-keygen','-t','ed25519','-N','','-C','security-manager-v2-sbom-fixed','-f',str(key)],capture_output=True,text=True);assert p.returncode==0
pub=key.with_suffix('.pub').read_text().strip()
deps=[('org.apache.commons','commons-lang3','3.20.0'),('commons-io','commons-io','2.22.0'),('org.slf4j','slf4j-api','2.0.18'),('com.fasterxml.jackson.core','jackson-core','2.17.2'),('com.fasterxml.jackson.core','jackson-annotations','2.21'),('com.fasterxml.jackson.core','jackson-databind','2.17.2'),('org.yaml','snakeyaml','2.6'),('com.google.code.gson','gson','2.13.2'),('commons-codec','commons-codec','1.22.0'),('org.apache.commons','commons-compress','1.28.0')]
pom='<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>security.demo</groupId><artifactId>java-dependencies-demo</artifactId><version>1.0.0</version><dependencies>'+''.join('<dependency><groupId>'+g+'</groupId><artifactId>'+a+'</artifactId><version>'+v+'</version></dependency>'for g,a,v in deps)+'</dependencies><build><plugins><plugin><groupId>org.cyclonedx</groupId><artifactId>cyclonedx-maven-plugin</artifactId><version>2.9.3</version><executions><execution><phase>process-resources</phase><goals><goal>makeAggregateBom</goal></goals></execution></executions><configuration><schemaVersion>1.6</schemaVersion><outputFormat>json</outputFormat><outputDirectory>${project.build.outputDirectory}/META-INF/sbom</outputDirectory><outputName>application.cdx</outputName><includeLicenseText>false</includeLicenseText></configuration></plugin></plugins></build></project>'
packet={'entry':(ROOT/'infra/security/manager-v2/sbom/linux-entry.py').read_text(),'pom':pom,'pub':pub,'inputSha':hashlib.sha256(pom.encode()).hexdigest()}
code=r'''
import pathlib,json,subprocess,pwd,os,shutil,hashlib,sys
x=json.load(sys.stdin);root=pathlib.Path('/var/lib/security-sbom')
assert not root.exists(),'SBOM_ROOT_ALREADY_EXISTS'
try:pwd.getpwnam('security-sbom');raise RuntimeError('ACCOUNT_EXISTS')
except KeyError:pass
subprocess.check_call(['useradd','--system','--home-dir',str(root),'--no-create-home','--shell','/bin/sh','security-sbom'])
u=pwd.getpwnam('security-sbom');root.mkdir(mode=0o755)
(root/'runs').mkdir(mode=0o700);os.chown(root/'runs',u.pw_uid,u.pw_gid)
(root/'fixture').mkdir();(root/'fixture/pom.xml').write_text(x['pom']);(root/'entry.py').write_text(x['entry']);(root/'approval.json').write_text(json.dumps({'uid':u.pw_uid,'sourceArtifactSha256':x['inputSha']}));(root/'settings.xml').write_text('<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><offline>true</offline><interactiveMode>false</interactiveMode></settings>')
shutil.copytree('/var/jenkins_home/.m2/wrapper/dists/apache-maven-3.9.16/56ba1f9f',root/'maven',symlinks=False)
# Only public Maven repository artifacts, no settings.xml, credentials or user home.
repo=pathlib.Path('/var/jenkins_home/.m2/repository');dest=root/'repository';dest.mkdir()
for namespace in ['org','com','net','io','jakarta','javax','junit','commons-io','commons-codec','commons-logging','commons-cli','commons-beanutils','commons-digester','commons-collections','commons-lang','commons-validator','xml-apis','xerces','aopalliance','ch','classworlds','backport-util-concurrent']:
 source=repo/namespace
 if source.is_dir():shutil.copytree(source,dest/namespace,ignore=shutil.ignore_patterns('*.lastUpdated','*.lock','*.tmp'),symlinks=False)
for base in [root/'maven',root/'repository',root/'fixture']:
 for p in base.rglob('*'):
  if p.is_file():p.chmod(0o555 if p.stat().st_mode&0o111 else 0o444)
  elif p.is_dir():p.chmod(0o555)
 base.chmod(0o555)
for p in ['entry.py','approval.json','settings.xml']:(root/p).chmod(0o444)
(root/'.ssh').mkdir(mode=0o755)
line='restrict,command="/usr/bin/setpriv --no-new-privs /usr/bin/python3 /var/lib/security-sbom/entry.py" '+x['pub']+'\n'
(root/'.ssh/authorized_keys').write_text(line);(root/'.ssh/authorized_keys').chmod(0o644)
print(json.dumps({'identity':{'user':'security-sbom','uid':u.pw_uid,'gid':u.pw_gid},'root':str(root),'inputSha256':x['inputSha'],'toolSha256':hashlib.sha256((dest/'org/cyclonedx/cyclonedx-maven-plugin/2.9.3/cyclonedx-maven-plugin-2.9.3.jar').read_bytes()).hexdigest(),'ssh':'restrict + fixed command; no arbitrary path/scenario','privileges':'no sudo, no docker/kubernetes groups','generationCount':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',json.dumps(packet)+'\n',timeout=3)) if False else None
# Read code via -c; packet is stdin, never a shell interpolation.
x=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(packet),timeout=120))
with(HERE/'identity.json').open('x')as f:json.dump(x,f,indent=2)
(ROOT/'infra/security/manager-v2/sbom/pom.xml').write_text(pom+'\n')
print(json.dumps(x))
