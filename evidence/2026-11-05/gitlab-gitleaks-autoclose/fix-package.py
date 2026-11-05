"""Update only the existing nonproduction Job with fixed trusted dispatch code. No build."""
import base64,gzip,hashlib,json,re,runpy,shlex,sys,tempfile,subprocess
from pathlib import Path
from urllib.parse import urlencode
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
pre=json.loads((OUT/'approved-preflight.json').read_text())
commit=json.loads((OUT/'prepared.json').read_text())['commit']
seen={}
def add(file):
 file=file.resolve()
 assert file.is_relative_to(ROOT) and file.is_file()
 name=str(file.relative_to(ROOT))
 if name in seen:return
 text=file.read_text()
 if name=='infra/jenkins/gitlab-push-demo/run-clean.mjs':
  text=text.replace('@TRUSTED_HOST_KEY@',pre['host']['hostKey'])
 seen[name]=text
 if file.suffix=='.mjs':
  for rel in re.findall(r"""(?:from\s*|import\s*\(|new URL\s*\()\s*['"](\.[^'"]+)['"]""",text):
   child=(file.parent/rel).resolve()
   if child.is_file() and child.is_relative_to(ROOT/'infra'):add(child)
add(ROOT/'infra/jenkins/gitlab-push-demo/run-clean.mjs')
# Import verification only: never run the dispatcher or call SSH during packaging.
with tempfile.TemporaryDirectory(prefix='gitleaks-dispatch-import-',dir='/tmp') as d:
 temp=Path(d)
 for name,text in seen.items():
  q=temp/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_text(text)
 subprocess.run(['/opt/homebrew/bin/node','--input-type=module','-e',
 'await import('+json.dumps((temp/'infra/security/manager-v2/view/linux-gitleaks.mjs').as_uri())+');'],
 check=True,capture_output=True,text=True,timeout=8)
packed=gzip.compress(json.dumps(seen,separators=(',',':')).encode(),mtime=0)
digest=hashlib.sha256(packed).hexdigest()
b64=base64.b64encode(packed).decode()
chunks='['+','.join("'"+b64[i:i+12000]+"'" for i in range(0,len(b64),12000))+'].join(\'\')'
template=(ROOT/'infra/jenkins/gitlab-push-demo/Pipeline.groovy').read_text()
pipeline=template.replace('@EXPECTED_REPOSITORY@','http://gitlab-578fd9dcbb-rhbx8/root/petclinic-platform.git').replace('@EXPECTED_COMMIT@',commit).replace('@TRUSTED_PACKAGE_CHUNKS@',chunks).replace('@TRUSTED_PACKAGE_SHA@',digest)
assert '@EXPECTED_' not in pipeline and '@TRUSTED_' not in pipeline and len(packed)<196608
r=json.loads(p['m']['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(p['NODE']),
 json.dumps({'path':'/pipeline-model-converter/validate','method':'POST','type':'application/x-www-form-urlencoded',
 'body':urlencode({'jenkinsfile':pipeline}),'timeout':20000}),30))
assert r['status']==200 and 'Jenkinsfile successfully validated' in r['body'],r['body'][:900]
code=p['PREFIX']+r"""
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import java.security.MessageDigest
def hash={String s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def job=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !job.isBuilding() && job.lastBuild.number==3 && job.lastBuild.result.toString()=='FAILURE'
assert hash(job.configFile.asString())=='@BEFORE_SHA@'
assert j.lastBuild.number==270 && hash(j.configFile.asString())=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
assert api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id=='d21b1271982bd4d8d90857b889c312d522779fc2'
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105'
def backup=new File(job.rootDir,'config.before-gitleaks-autoclose-'+System.currentTimeMillis()+'.xml')
assert backup.createNewFile()
backup.setReadable(false,false);backup.setWritable(false,false)
assert backup.setReadable(true,true)&&backup.setWritable(true,true)
backup.bytes=job.configFile.file.bytes
String previous=hash(backup.text)
job.definition=new CpsFlowDefinition(@PIPELINE@,true);job.save()
assert job.triggers.values().size()==1 && job.triggers.values().first().includeBranchesSpec=='security-demo/gitlab-push-20261105'
assert job.definition.sandbox
println(JsonOutput.toJson([job:job.fullName,lastBuild:job.lastBuild.number,buildStarted:false,
 backup:backup.absolutePath,backupSha256:previous,definitionSha256:hash(job.configFile.asString()),
 pipelineSha256:hash(job.definition.script),pinnedCommit:'@COMMIT@',productionJobUnchanged:true,
 credentialsBound:['security-gitleaks-demo-ssh'],webhookChanged:false]))
"""
for k,v in {'BEFORE_SHA':json.loads((OUT/'job-installed.json').read_text())['definitionSha256'],'PIPELINE':"new String(["+','.join("'"+base64.b64encode(pipeline.encode()).decode()[i:i+12000]+"'" for i in range(0,len(base64.b64encode(pipeline.encode()).decode()),12000))+"].join('').decodeBase64(),'UTF-8')",'COMMIT':commit}.items():code=code.replace('@'+k+'@',v)
result=p['script'](code)
result['trustedPackage']={'files':len(seen),'gzipBytes':len(packed),'sha256':digest,'localImport':'VERIFIED',
 'sourceHashes':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in seen.items()}}
result['lint']=r['body'].strip()
with (OUT/'job-fixed.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps({k:v for k,v in result.items() if k!='trustedPackage'}))
print(json.dumps({k:v for k,v in result['trustedPackage'].items() if k!='sourceHashes'}))
