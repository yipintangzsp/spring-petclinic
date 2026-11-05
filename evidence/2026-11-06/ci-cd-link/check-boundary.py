"""Read only exact demo stage lines and protected-main access levels."""
import json
import runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
prior=OUT.parents[1]/'2026-11-05'
p=runpy.run_path(str(prior/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
def lines=demo.definition.script.readLines().findAll{String s->s.trim().startsWith('stage(') || s.contains('sshUserPrivateKey(') || s.contains('Demo Publish reached')}.collect{it.trim().take(250)}
def protection=api('/projects/12/protected_branches/main')
println(JsonOutput.toJson([job:demo.fullName,reviewedFixedStageLines:lines,
 main:[name:protection.name,allowForcePush:protection.allow_force_push,pushAccess:protection.push_access_levels.collect{[level:it.access_level,description:it.access_level_description,deployKeyId:it.deploy_key_id,userId:it.user_id,groupId:it.group_id]}],
 metadataCaveat:'The earlier hasGitOpsStage substring field is not proof of a GitOps stage. Use these exact stage lines instead.',writes:0]))
'''
r=p['script'](code)
with (OUT/'boundary.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
