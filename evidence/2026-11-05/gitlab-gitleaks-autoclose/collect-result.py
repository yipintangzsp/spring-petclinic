"""Read only this demo build's whitelisted JSON artifacts; never credential files."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
def b=Jenkins.instance.getItemByFullName('security-gitlab-push-demo').getBuildByNumber(4)
assert b.result.toString()=='SUCCESS' && !b.building
assert b.causes.size()==1 && b.causes.first().class.name=='com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause'
assert b.causes.first().data.after=='d21b1271982bd4d8d90857b889c312d522779fc2'
def names=b.artifacts.collect{it.relativePath}
assert names.size()>5 && names.size()<30 && names.every{it.matches('evidence/(artifact/)?[-a-zA-Z0-9_.]+[.]json')}
def files=names.collectEntries{name->
 def f=new File(b.artifactsDir,name)
 assert f.canonicalPath.startsWith(b.artifactsDir.canonicalPath+'/evidence/') && f.length()<131072
 [(name):f.bytes.encodeBase64().toString()]
}
println(JsonOutput.toJson([build:4,files:files]))
'''
r=p['script'](code)
with (OUT/'build-artifacts.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps({'build':r['build'],'artifactCount':len(r['files']),'paths':list(r['files'])}))
