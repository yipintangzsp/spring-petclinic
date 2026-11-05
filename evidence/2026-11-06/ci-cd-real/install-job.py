"""Update existing demo only, with fixed trusted package and one exact trigger SHA."""
from common import *
import base64,gzip,hashlib,re,shlex
from urllib.parse import urlencode
prep=json.loads((OUT/'prepared.json').read_text());before=json.loads((OUT/'before.json').read_text())
host=json.loads((PRIOR/'gitlab-gitleaks-autoclose/approved-preflight.json').read_text())['host']['hostKey']
files={}
def add(file):
 file=file.resolve();assert file.is_relative_to(ROOT/'infra')
 name=str(file.relative_to(ROOT))
 if name in files:return
 text=file.read_text().replace('@TRUSTED_HOST_KEY@',host);files[name]=text
 for rel in re.findall(r'''(?:from\s*|import\s*\(|new URL\s*\()\s*['"](\.[^'"]+)['"]''',text):
  child=(file.parent/rel).resolve()
  if child.is_file() and child.is_relative_to(ROOT/'infra'):add(child)
for name in ['run-clean.mjs','run-cd.mjs']:add(ROOT/'infra/jenkins/gitlab-push-demo'/name)
packed=gzip.compress(json.dumps(files,separators=(',',':')).encode(),mtime=0)
assert len(packed)<196608
b64=base64.b64encode(packed).decode();chunks='['+','.join("'"+b64[i:i+12000]+"'" for i in range(0,len(b64),12000))+"].join('')"
pipeline=(ROOT/'infra/jenkins/gitlab-push-demo/Pipeline.groovy').read_text().replace('@EXPECTED_REPOSITORY@','http://gitlab-578fd9dcbb-rhbx8/root/petclinic-platform.git').replace('@EXPECTED_COMMIT@',prep['triggerCommit']).replace('@TRUSTED_PACKAGE_CHUNKS@',chunks).replace('@TRUSTED_PACKAGE_SHA@',hashlib.sha256(packed).hexdigest())
result=json.loads(p['m']['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(p['NODE']),
 json.dumps({'path':'/pipeline-model-converter/validate','method':'POST','type':'application/x-www-form-urlencoded','body':urlencode({'jenkinsfile':pipeline}),'timeout':20000}),30))
assert result['status']==200 and 'Jenkinsfile successfully validated' in result['body']
encoded=base64.b64encode(pipeline.encode()).decode()
literal='['+','.join("'"+encoded[i:i+12000]+"'" for i in range(0,len(encoded),12000))+"].join('').decodeBase64()"
code=p['PREFIX']+r'''
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import java.security.MessageDigest
def hash={byte[] v->MessageDigest.getInstance('SHA-256').digest(v).encodeHex().toString()}
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !demo.isBuilding() && demo.lastBuild.number==@PREVIOUS_BUILD@ && demo.nextBuildNumber==@BUILD@
assert hash(demo.configFile.file.bytes)=='@BEFORE@'
assert j.lastBuild.number==270 && hash(j.configFile.file.bytes)=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
assert api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id=='@TRIGGER_BASE@'
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105'
def backup=new File(demo.rootDir,'config.before-ci-cd-'+System.currentTimeMillis()+'.xml');assert backup.createNewFile()
backup.setReadable(false,false);backup.setWritable(false,false);assert backup.setReadable(true,true)&&backup.setWritable(true,true);backup.bytes=demo.configFile.file.bytes
demo.definition=new CpsFlowDefinition(new String(@PIPELINE@,'UTF-8'),true);demo.save()
println(JsonOutput.toJson([job:demo.fullName,expectedBuild:demo.nextBuildNumber,pinnedTrigger:'@TRIGGER@',backup:backup.absolutePath,backupSha256:hash(backup.bytes),definitionSha256:hash(demo.configFile.file.bytes),productionJobUnchanged:true,buildStarted:false,webhookChanged:false]))
'''
for k,v in {'BUILD':str(prep['allowedBuild']),'PREVIOUS_BUILD':str(before.get('previousBuild',4)),'TRIGGER_BASE':prep['triggerBase'],'BEFORE':before['jobSha256'],'PIPELINE':literal,'TRIGGER':prep['triggerCommit']}.items():code=code.replace('@'+k+'@',v)
r=script(code);r['trustedPackage']={'files':len(files),'bytes':len(packed),'sha256':hashlib.sha256(packed).hexdigest()};r['pipelineLint']=result['body'].strip()
save('job-installed.json',r);print(json.dumps(r))
