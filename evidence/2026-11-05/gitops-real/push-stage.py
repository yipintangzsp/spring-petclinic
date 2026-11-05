"""One bounded actual git push of the requested prepared stage; no build API."""
import base64
import datetime
import hashlib
import json
import runpy
import sys
from pathlib import Path
OUT=Path(__file__).resolve().parent
stage=sys.argv[1];assert stage in ['baseline','updated','restored']
resume=sys.argv[2:] == ['--resume-after-output-fix']
assert not sys.argv[2:] or resume
if resume:
 assert stage=='restored' and (OUT/'push-restored-attempt.json').exists() and not (OUT/'push-restored.json').exists()
 observed=json.loads((OUT/'restored-incomplete.json').read_text())
 assert observed['configMap']['data']=={'demo-stage':'updated'}
plan=json.loads((OUT/'prepared.json').read_text());part=plan['commits'][stage]
before={'baseline':None,'updated':plan['commits']['baseline']['commit'],'restored':plan['commits']['updated']['commit']}[stage]
bundle=(OUT/part['bundle']).read_bytes()
assert len(bundle)==part['bytes'] and hashlib.sha256(bundle).hexdigest()==part['sha256']
attempt='push-'+stage+('-resume-attempt.json' if resume else '-attempt.json')
with (OUT/attempt).open('x') as f:json.dump({'stage':stage,'branch':plan['branch'],'expectedBefore':before,'after':part['commit'],'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'resumeAfterOutputFix':resume},f,indent=2)
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
def hash={byte[] v->MessageDigest.getInstance('SHA-256').digest(v).encodeHex().toString()}
def branch='security-demo/gitops-20261105',expected=@BEFORE@,sha='@COMMIT@'
assert api('/projects/12').path_with_namespace=='root/petclinic-platform'
assert api('/projects/12/repository/branches/main').commit.id=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
def old=api('/projects/12/repository/branches?search=security-demo%2Fgitops-20261105').find{it.name==branch}
assert expected==null?old==null:old?.commit?.id==expected
assert j.lastBuild.number==270 && !j.isBuilding()
assert api('/projects/12/hooks').every{!it.push_events || it.push_events_branch_filter in ['main','security-demo/gitlab-push-20261105']}
def tmp=java.nio.file.Files.createTempDirectory('petclinic-gitops-push-').toFile()
def run={List args,Map extra=[:]->
 def pb=new ProcessBuilder(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','http.followRedirects=false']+args)
 pb.directory(tmp);pb.redirectErrorStream(true);def e=pb.environment();e.clear()
 e.putAll([PATH:'/usr/bin:/bin',HOME:tmp.absolutePath,LANG:'C',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_CONFIG_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0',GIT_NO_REPLACE_OBJECTS:'1']);e.putAll(extra)
 def proc=pb.start();proc.outputStream.close();def output=new StringBuffer();def reader=proc.consumeProcessOutputStream(output)
 if(!proc.waitFor(16,TimeUnit.SECONDS)){proc.destroyForcibly();throw new IllegalStateException('Bounded git timed out; inspect remote branch before any retry')}
 reader.join(2000);assert !reader.alive:'Git output collector did not finish'
 assert proc.exitValue()==0:'Bounded git failed, exit '+proc.exitValue()
 output.toString().trim()
}
try{
 byte[] bytes='@BUNDLE@'.decodeBase64();assert hash(bytes)=='@HASH@'
 def bundle=new File(tmp,'demo.bundle');bundle.bytes=bytes
 run(['init','-q','--template=']);run(['bundle','verify',bundle.absolutePath]);run(['fetch','--no-tags',bundle.absolutePath,'refs/heads/'+branch])
 assert run(['rev-parse','FETCH_HEAD'])==sha
 assert run(['ls-tree','-r','--name-only','FETCH_HEAD'])=='infra/devops-lab/gitops-demo/configmap.yaml'
 def manifest=new JsonSlurper().parseText(run(['show','FETCH_HEAD:infra/devops-lab/gitops-demo/configmap.yaml']))
 assert manifest.kind=='ConfigMap' && manifest.metadata.name=='petclinic-gitops-demo' && manifest.metadata.namespace=='devsecops-test' && manifest.data==['demo-stage':'@VALUE@']
 assert run(['log','-1','--format=%B','FETCH_HEAD']).contains('[skip ci]')
 def ask=new File(tmp,'askpass');ask.text='#!/bin/sh\ncase "$1" in *Username*) printf "%s\\n" oauth2 ;; *Password*) printf "%s\\n" "$GITLAB_TOKEN" ;; *) exit 1 ;; esac\n';assert ask.setExecutable(true,true)
 String at=new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC'))
 def output=run(['push','--porcelain','--no-verify','-o','ci.skip','http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git','FETCH_HEAD:refs/heads/'+branch],[GIT_ASKPASS:ask.absolutePath,GITLAB_TOKEN:cred.password.plainText])
 assert api('/projects/12/repository/branches/security-demo%2Fgitops-20261105').commit.id==sha
 assert api('/projects/12/repository/branches/main').commit.id=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
 def pipelines=api('/projects/12/pipelines?ref=security-demo%2Fgitops-20261105&per_page=5').collect{[id:it.id,status:it.status,sha:it.sha]}
 assert pipelines.every{it.status=='skipped'}:'Unexpected GitLab execution; stop'
 println(JsonOutput.toJson([stage:'@STAGE@',branch:branch,commit:sha,gitPushExit:0,pushInvocations:1,ciSkip:true,pushOutput:output,startedAt:at,
 completedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),pipelines:pipelines,mainUnchanged:true,jenkinsBuildApiCalled:false]))
}finally{assert tmp.canonicalPath.startsWith('/tmp/petclinic-gitops-push-');assert tmp.deleteDir()}
'''
for key,value in {'BEFORE':json.dumps(before),'COMMIT':part['commit'],'BUNDLE':base64.b64encode(bundle).decode(),'HASH':part['sha256'],'VALUE':part['value'],'STAGE':stage}.items():code=code.replace('@'+key+'@',value)
result=p['script'](code)
with (OUT/('push-'+stage+'.json')).open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
