"""Read-only live Jenkins inventory through the already authorized relay.

Never prints credentials, job XML or console text. Uses strict trusted host keys.
No build trigger, config update, scanner, approval, signing, Git push or deploy.
"""
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, '/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE

base = pathlib.Path(__file__).parent
ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=6', '-o', 'ConnectionAttempts=1',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'HostName=192.168.64.11',
       '-o', 'HostKeyAlias=192.168.1.58', 'zhang@192.168.1.58']
script = r'''
import groovy.json.JsonOutput
import java.security.MessageDigest
def hash={ s -> MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString() }
def names=['petclinic-security-audit','petclinic-ci']
def jobs=Jenkins.instance.allItems.findAll{j-> names.contains(j.fullName) || j.fullName.contains('security-audit')}
def rows=jobs.collect{j->
 def d=j.definition
 def script=d?.metaClass?.hasProperty(d,'script')?d.script:null
 def latest=j.lastBuild
 def artifacts=latest?latest.artifacts:[]
 def summary=artifacts.find{it.relativePath=='.devsecops/security-summary.json'}
 def summaryText=null
 if(summary) { def f=new File(latest.artifactsDir,summary.relativePath);if(f.isFile())summaryText=f.getText('UTF-8') }
 def scm=d?.metaClass?.hasProperty(d,'scm')?d.scm:null
 [job:j.fullName,disabled:j.disabled,building:latest?.building,definitionClass:d?.getClass()?.name,
  scriptSha256:script==null?null:hash(script),scriptPath:d?.metaClass?.hasProperty(d,'scriptPath')?d.scriptPath:null,
  scmBranches:scm?.metaClass?.hasProperty(scm,'branches')?scm.branches.collect{it.name}:null,
  stages:script==null?[]:(script=~/stage\(['"]([^'"]+)['"]\)/).collect{it[1]},
  latestBuild:latest?.number,result:latest?.result?.toString(),timestamp:latest?.startTimeInMillis,
  artifactCount:artifacts.size(),summarySha256:summaryText==null?null:hash(summaryText),summary:summaryText==null?null:new groovy.json.JsonSlurperClassic().parseText(summaryText),
  resultArtifactPaths:artifacts.findAll{it.relativePath.contains('policy')||it.relativePath.endsWith('security-manager.json')||it.relativePath.endsWith('security-summary.json')}.collect{it.relativePath},
  checkoutRevisions:latest==null?[]:latest.getActions(hudson.plugins.git.util.BuildData).collectMany{a->a.buildsByBranchName.values().collect{it.revision.sha1String}}.unique()]
}
println(JsonOutput.toJson([collectedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX"),jobs:rows]))
'''
if len(sys.argv) == 2 and sys.argv[1] == 'workspace':
    script = r'''
import groovy.json.JsonOutput
import java.security.MessageDigest
import org.jenkinsci.plugins.workflow.graph.FlowGraphWalker
import org.jenkinsci.plugins.workflow.actions.WorkspaceAction
def b=Jenkins.instance.getItemByFullName('petclinic-ci').lastBuild
def actions=[]
new FlowGraphWalker(b.execution).each{n->def a=n.getAction(WorkspaceAction);if(a)actions.add([node:a.node,path:a.path])}
def paths=['Jenkinsfile.security-audit','vars/securityManager.groovy','resources/security-manager/petclinic-adapter.json',
 'infra/security/security-summary.mjs','infra/security/scanner-runtime.mjs','infra/security/secrets-gate.mjs',
 'infra/security/runtime/health.mjs','infra/security/admission-gate.mjs','infra/security/rbac-contract.mjs',
 'infra/security/governance/kubescape.mjs','infra/security/governance/defectdojo.mjs','infra/security/signing.mjs',
 'infra/security/promotion/evidence.mjs','infra/security/promotion/contract.mjs','infra/security/promotion/sign-approve.mjs',
 'infra/security/promotion/promote.mjs','infra/security/policy/engine.mjs','infra/security/policy/versions/baseline-v1.json',
 'infra/security/policy/versions/promotion-baseline-v1.json','infra/security/policy/versions/regression-baseline-v1.json',
 'infra/security/summary-v2/owner.mjs']
def spaces=actions.unique().collect{a->
 def computer=a.node?Jenkins.instance.getNode(a.node)?.toComputer():Jenkins.instance.toComputer()
 def workspace=computer?.channel?new hudson.FilePath(computer.channel,a.path):null
 def files=paths.collectEntries{p->
  def f=workspace?.child(p)
  [(p):f?.exists()?[exists:true,sha256:MessageDigest.getInstance('SHA-256').digest(f.readToString().getBytes('UTF-8')).encodeHex().toString()]:[exists:false]]
 }
 [workspace:a,online:computer?.online,files:files]
}
println(JsonOutput.toJson([build:b.number,workspaces:spaces]))
'''
if len(sys.argv) == 2 and sys.argv[1] == 'freeze-active':
    script = r'''
import groovy.json.JsonOutput
import org.jenkinsci.plugins.workflow.graph.FlowGraphWalker
import org.jenkinsci.plugins.workflow.actions.WorkspaceAction
def j=Jenkins.instance.getItemByFullName('petclinic-ci'),b=j.lastBuild
def spaces=[]
new FlowGraphWalker(b.execution).each{n->def a=n.getAction(WorkspaceAction);if(a&&!a.path.contains('@script'))spaces.add(a)}
def a=spaces[0]
def computer=a.node?Jenkins.instance.getNode(a.node)?.toComputer():Jenkins.instance.toComputer()
def workspace=new hudson.FilePath(computer.channel,a.path)
def paths=['Jenkinsfile.security-audit','vars/securityManager.groovy','vars/securityProvenance.groovy','vars/securityBuildProvenance.groovy',
 'resources/security-manager/petclinic-adapter.json','infra/security/security-summary.mjs','resources/security-manager/summary.mjs',
 'infra/security/manager/summary.mjs','infra/security/gate.sh','infra/security/promotion/evidence.mjs','infra/security/promotion/contract.mjs',
 'infra/security/promotion/sign-approve.mjs','infra/security/promotion/promote.mjs']
def files=paths.collectEntries{p->def f=workspace.child(p);[(p):f.exists()?f.readToString().getBytes('UTF-8').encodeBase64().toString():null]}
def actions=b.getAllActions().findAll{it.getClass().name.contains('LibrariesAction')}
def libraries=actions.collectMany{x->x.libraries.collect{l->[name:l.name,version:l.version]}}
println(JsonOutput.toJson([job:j.fullName,build:b.number,workspace:a.path,filesBase64:files,libraries:libraries]))
'''
payload = {'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded',
           'body':urllib.parse.urlencode({'script':script}),'timeout':45000}
command = 'sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e ' + shlex.quote(NODE)
result = subprocess.run(ssh + [command],input=json.dumps(payload),capture_output=True,text=True,timeout=60)
if result.returncode:
    (base/'live-inspection-error.json').write_text(json.dumps({'exit':result.returncode,'stderr':result.stderr[-1500:]},indent=2)+'\n')
    raise SystemExit('SSH/Jenkins inspection failed; see protected bounded error record')
response = json.loads(result.stdout)
if response['status'] != 200:
    (base/'live-inspection-error.json').write_text(json.dumps({'httpStatus':response['status'],'bodySha256':hashlib.sha256(response['body'].encode()).hexdigest(),'bodyExcerpt':response['body'][:1000]},indent=2)+'\n')
    raise SystemExit('Jenkins inspection rejected; no further operation')
data = json.loads(response['body'].split('\n',1)[0])
if len(sys.argv) == 2 and sys.argv[1] == 'freeze-active':
    import base64
    tree = base/'active-v1-tree'
    if tree.exists():
        raise SystemExit('Refusing to overwrite active V1 snapshot')
    tree.mkdir()
    files = {}
    for relative, encoded in data.pop('filesBase64').items():
        if encoded is None:
            files[relative] = {'exists':False}
            continue
        if relative.startswith('/') or '..' in pathlib.PurePosixPath(relative).parts:
            raise SystemExit('Invalid snapshot path')
        content = base64.b64decode(encoded,validate=True)
        target = tree/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(content)
        files[relative] = {'exists':True,'sha256':hashlib.sha256(content).hexdigest(),'bytes':len(content)}
    data['files'] = files
    data['classification'] = 'REAL_READ_ONLY_ACTIVE_WORKSPACE_SNAPSHOT_NOT_HISTORICAL_EXECUTION_TRACE'
    (base/'ACTIVE_V1_IDENTITY.json').write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps({'activeSourceFiles':len(files),'libraries':data['libraries'],'remoteModified':False}))
    raise SystemExit(0)
name = 'live-workspace-hashes.json' if len(sys.argv) == 2 else 'live-jenkins-baseline.json'
(base/name).write_text(json.dumps(data,indent=2)+'\n')
if len(sys.argv) == 2:
    print(json.dumps(data))
else:
    print(json.dumps({'jobs':[{k:j.get(k) for k in ['job','definitionClass','scriptPath','scriptSha256','latestBuild','result','artifactCount','summarySha256']} for j in data['jobs']]}))
