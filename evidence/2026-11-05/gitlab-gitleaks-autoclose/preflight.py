"""Read-only execution-path check. Never reads private key values or starts a scan/build."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
old=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=old['PREFIX']+"""
import com.cloudbees.plugins.credentials.common.StandardCredentials
import hudson.security.ACL
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
def other=Jenkins.instance.getItemByFullName('security-gitleaks-demo')
def visible=CredentialsProvider.lookupCredentialsInItem(StandardCredentials.class,demo,ACL.SYSTEM2,[])
def candidates=visible.findAll{it.class.name.contains('SSH')||it.id.toLowerCase().contains('gitleaks')}
def project=api('/projects/12')
println(JsonOutput.toJson([
 job:[name:demo.fullName,lastBuild:demo.lastBuild.number,result:demo.lastBuild.result.toString(),script:demo.definition.script,sandbox:demo.definition.sandbox,
 triggers:demo.triggers.values().collect{[type:it.class.name,include:it.includeBranchesSpec,secretConfigured:it.secretToken?true:false]}],
 previousGitleaksDemo:[name:other.fullName,lastBuild:other.lastBuild.number,description:other.description],
 availableScannerCredentials:candidates.collect{[id:it.id,type:it.class.name,username:it.hasProperty('username')?it.username:null]},
 jenkinsSshDirectoryEntries:new File('/var/jenkins_home/.ssh').isDirectory()?new File('/var/jenkins_home/.ssh').listFiles().collect{it.name}:[],
 hooks:api('/projects/12/hooks').collect{[id:it.id,url:it.url,branch:it.push_events_branch_filter,push:it.push_events]},
 branch:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id,
 production:[lastBuild:j.lastBuild.number,result:j.lastBuild.result.toString()],
 project:[id:project.id,path:project.path_with_namespace]
]))
"""
if __name__=='__main__':
 r=old['script'](code)
 with (OUT/'execution-path.json').open('x') as f:json.dump(r,f,indent=2)
 print(json.dumps(r))
