import pathlib,json,runpy,base64,shlex,urllib.parse
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');prep=json.loads((h/'prepared.json').read_text());assert json.loads((h/'negative-tests.json').read_text())['newScans']==0
info=p['script'](p['PREFIX']+"println(JsonOutput.toJson([repo:api('/projects/12').http_url_to_repo,branch:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id]))")
assert info['branch']==prep['triggerBase']
key=json.loads(pathlib.Path('evidence/2026-11-05/gitlab-gitleaks-autoclose/approved-preflight.json').read_text())['host']['hostKey']
s=pathlib.Path('infra/security/manager-v2/ci/manager-demo.Pipeline.groovy').read_text().replace('@SOURCE_REPOSITORY@',info['repo']).replace('@COMMIT@',prep['triggerCommit']).replace('@HOST_KEY@',key)
r=json.loads(p['m']['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(p['NODE']),json.dumps({'path':'/pipeline-model-converter/validate','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'jenkinsfile':s}),'timeout':20000}),30));assert r['status']==200 and 'Jenkinsfile successfully validated'in r['body'],r['body'][:500]
b64=base64.b64encode(s.encode()).decode()
code=p['PREFIX']+r'''
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import java.security.MessageDigest
def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo');assert !d.isBuilding() && d.nextBuildNumber==7 && d.lastBuild.number==6
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105'
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()};def old=hash(d.definition.script.getBytes('UTF-8'));assert old=='3480fb1418a7d790a05d334f43b58df382ac52d81557ae5f203690093f73e6ff'
def backup=new File(d.rootDir,'config.before-manager-ci-20261107.xml');assert backup.createNewFile();backup.setReadable(false,false);backup.setWritable(false,false);backup.setReadable(true,true);backup.setWritable(true,true);backup.bytes=d.configFile.file.bytes
String pipeline=new String('@PIPELINE@'.decodeBase64(),'UTF-8');assert !pipeline.contains('run-cd.mjs')&&!pipeline.contains('security-gitops-demo-ssh');d.definition=new CpsFlowDefinition(pipeline,true);d.save();println(JsonOutput.toJson([job:d.fullName,nextBuild:d.nextBuildNumber,backup:backup.absolutePath,definitionBeforeSha256:old,definitionAfterSha256:hash(pipeline.bytes),productionJobModified:false,buildStarted:false]))
'''
x=p['script'](code.replace('@PIPELINE@',b64));x['sourceRepository']=info['repo'];x['lint']='PASSED'
with(h/'job-installed.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
