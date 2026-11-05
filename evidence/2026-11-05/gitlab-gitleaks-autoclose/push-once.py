"""Exactly one real git push to the pinned non-production branch; no Jenkins Build API."""
import base64,datetime,hashlib,json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
plan=json.loads((OUT/'prepared.json').read_text())
installed=json.loads((OUT/'job-installed.json').read_text())
bundle=base64.b64decode(plan['bundleBase64'])
assert len(bundle)==plan['bundleBytes'] and hashlib.sha256(bundle).hexdigest()==plan['bundleSha256']
with (OUT/'push-attempt.json').open('x') as f:json.dump({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'commit':plan['commit'],'branch':plan['branch'],'gitPushInvocationBudget':1},f,indent=2)
code=p['PREFIX']+r"""
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
assert api('/projects/12/repository/branches/main').commit.id=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
assert api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id=='37e28037c1d10ec74b5cb8acb212b1ccf4ee7b4b'
def hooks=api('/projects/12/hooks')
assert hooks.size()==2 && hooks.find{it.id==4}.push_events_branch_filter=='main'
assert hooks.find{it.id==5}.push_events_branch_filter=='security-demo/gitlab-push-20261105'
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert demo.lastBuild.number==2 && !demo.isBuilding() && demo.definition.sandbox
assert hash(demo.definition.script.getBytes('UTF-8'))=='@PIPELINE_HASH@'
assert j.lastBuild.number==270 && !j.isBuilding()
def tmp=java.nio.file.Files.createTempDirectory('gitlab-push-demo-').toFile()
assert tmp.canonicalPath.startsWith('/tmp/gitlab-push-demo-')
def run={List args,Map more=[:],int seconds=15->
 def pb=new ProcessBuilder(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','http.followRedirects=false']+args)
 pb.directory(tmp);pb.redirectErrorStream(true)
 def e=pb.environment();e.clear()
 e.putAll([PATH:'/usr/bin:/bin',HOME:tmp.absolutePath,LANG:'C',GIT_CONFIG_GLOBAL:'/dev/null',
 GIT_CONFIG_SYSTEM:'/dev/null',GIT_CONFIG_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0',GIT_NO_REPLACE_OBJECTS:'1'])
 e.putAll(more)
 def proc=pb.start();proc.outputStream.close()
 def output=new StringBuffer();proc.consumeProcessOutput(output,output)
 assert proc.waitFor(seconds,TimeUnit.SECONDS):'Bounded git operation timed out'
 assert proc.exitValue()==0:'Bounded git operation failed with exit '+proc.exitValue()
 output.toString().trim()
}
try{
 byte[] bytes='@BUNDLE@'.decodeBase64()
 assert bytes.length==@BUNDLE_BYTES@ && hash(bytes)=='@BUNDLE_HASH@'
 def bundle=new File(tmp,'demo.bundle');bundle.bytes=bytes
 run(['init','-q','--template='])
 new File(tmp,'.git/objects/info/alternates').text='/var/jenkins_home/workspace/petclinic-ci/.git/objects\n'
 def askpass=new File(tmp,'askpass')
 askpass.text='#!/bin/sh\ncase "$1" in *Username*) printf "%s\\n" oauth2 ;; *Password*) printf "%s\\n" "$GITLAB_TOKEN" ;; *) exit 1 ;; esac\n'
 assert askpass.setExecutable(true,true)

 run(['fetch','--no-tags','http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git','refs/heads/security-demo/gitlab-push-20261105'],[GIT_ASKPASS:askpass.absolutePath,GITLAB_TOKEN:cred.password.plainText],20)
 assert run(['rev-parse','FETCH_HEAD'])=='37e28037c1d10ec74b5cb8acb212b1ccf4ee7b4b'
 run(['bundle','verify',bundle.absolutePath])
 run(['fetch','--no-tags',bundle.absolutePath,'refs/heads/security-demo/gitlab-push-20261105'])
 assert run(['rev-parse','FETCH_HEAD'])=='@COMMIT@'
 assert run(['diff-tree','--no-commit-id','--name-only','-r','FETCH_HEAD'])=='docs/security-demo-gitlab-push.md'
 String started=new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC'))
 String output=run(['push','--porcelain','--no-verify',
 'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',
 'FETCH_HEAD:refs/heads/security-demo/gitlab-push-20261105'],
 [GIT_ASKPASS:askpass.absolutePath,GITLAB_TOKEN:cred.password.plainText],35)
 assert api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id=='@COMMIT@'
 assert api('/projects/12/repository/branches/main').commit.id=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
 println(JsonOutput.toJson([gitPushInvocations:1,pushExitCode:0,branch:'security-demo/gitlab-push-20261105',
 commit:'@COMMIT@',startedAt:started,finishedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 pushOutput:output,productionMainUnchanged:true,jenkinsBuildApiCalled:false]))
}finally{
 assert tmp.canonicalPath.startsWith('/tmp/gitlab-push-demo-')
 assert tmp.deleteDir():'Task-owned push directory cleanup failed'
}
"""
for key,value in {'PIPELINE_HASH':installed['pipelineSha256'],'BUNDLE':base64.b64encode(bundle).decode(),
 'BUNDLE_BYTES':str(len(bundle)),'BUNDLE_HASH':plan['bundleSha256'],'COMMIT':plan['commit']}.items():
 code=code.replace('@'+key+'@',value)
result=p['script'](code)
with (OUT/'push-result.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
