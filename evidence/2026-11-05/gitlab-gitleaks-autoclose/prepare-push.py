"""Prepare a fast-forward documentation-only commit in a private temp repository. No push."""
import base64,hashlib,json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r"""
import java.util.concurrent.TimeUnit
import java.security.MessageDigest
assert api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id=='37e28037c1d10ec74b5cb8acb212b1ccf4ee7b4b'
def tmp=java.nio.file.Files.createTempDirectory('gitlab-gitleaks-prepare-').toFile()
def run={List args,Map extra=[:],String input=null->
 def pb=new ProcessBuilder(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false']+args)
 pb.directory(tmp);pb.redirectErrorStream(true);pb.environment().clear()
 pb.environment().putAll([PATH:'/usr/bin:/bin',HOME:tmp.absolutePath,LANG:'C',
 GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_TERMINAL_PROMPT:'0',
 GIT_AUTHOR_NAME:'DevSecOps Demo',GIT_AUTHOR_EMAIL:'devsecops-demo@localhost',
 GIT_COMMITTER_NAME:'DevSecOps Demo',GIT_COMMITTER_EMAIL:'devsecops-demo@localhost'])
 pb.environment().putAll(extra)
 def proc=pb.start()
 if(input==null)proc.outputStream.close()
 else proc.outputStream.withWriter('UTF-8'){it<<input}
 def output=new StringBuffer();proc.consumeProcessOutput(output,output)
 assert proc.waitFor(18,TimeUnit.SECONDS)&&proc.exitValue()==0:'Bounded prepare Git operation failed'
 output.toString().trim()
}
try{
 run(['init','-q','--template='])
 new File(tmp,'.git/objects/info/alternates').text='/var/jenkins_home/workspace/petclinic-ci/.git/objects\n'
 def ask=new File(tmp,'askpass');ask.text='#!/bin/sh\ncase "$1" in *Username*) printf "%s\\n" oauth2 ;; *Password*) printf "%s\\n" "$GITLAB_TOKEN" ;; *) exit 1 ;; esac\n';assert ask.setExecutable(true,true)
 run(['fetch','--no-tags','http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',
 'refs/heads/security-demo/gitlab-push-20261105'],[GIT_ASKPASS:ask.absolutePath,GITLAB_TOKEN:cred.password.plainText])
 String base=run(['rev-parse','FETCH_HEAD']);assert base=='37e28037c1d10ec74b5cb8acb212b1ccf4ee7b4b'
 run(['read-tree',base])
 String blob=run(['hash-object','-w','--stdin'],[:],
 '# Isolated GitLab Gitleaks Clean demonstration\n\nFixed test branch triggers the existing restricted Linux Gitleaks runner.\nNo production credential, image publication, GitOps update or deployment.\n')
 run(['update-index','--add','--cacheinfo','100644',blob,'docs/security-demo-gitlab-push.md'])
 String tree=run(['write-tree'])
 String commit=run(['commit-tree',tree,'-p',base],[:],'demo: automatically verify restricted Gitleaks Clean\n')
 run(['update-ref','refs/heads/security-demo/gitlab-push-20261105',commit])
 assert run(['diff-tree','--no-commit-id','--name-only','-r',commit])=='docs/security-demo-gitlab-push.md'
 def bundle=new File(tmp,'demo.bundle')
 run(['bundle','create',bundle.absolutePath,'refs/heads/security-demo/gitlab-push-20261105','^'+base])
 byte[] bytes=bundle.bytes;assert bytes.length<65536
 println(JsonOutput.toJson([base:base,branch:'security-demo/gitlab-push-20261105',commit:commit,
 onlyChangedPath:'docs/security-demo-gitlab-push.md',bundleBytes:bytes.length,
 bundleSha256:MessageDigest.getInstance('SHA-256').digest(bytes).encodeHex().toString(),
 bundleBase64:bytes.encodeBase64().toString(),pushExecuted:false]))
}finally{assert tmp.canonicalPath.startsWith('/tmp/gitlab-gitleaks-prepare-');assert tmp.deleteDir()}
"""
r=p['script'](code)
bytes=base64.b64decode(r['bundleBase64'],validate=True)
assert hashlib.sha256(bytes).hexdigest()==r['bundleSha256']
with (OUT/'prepared.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps({k:v for k,v in r.items() if k!='bundleBase64'}))
