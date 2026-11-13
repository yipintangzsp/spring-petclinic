import runpy,pathlib,json,shlex,sys
sys.dont_write_bytecode=True
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
code=p['PREFIX']+'''
def hooks=api('/projects/12/hooks').findAll{it.id==5}.collect{h->def u=new URI(h.url);[id:h.id,url:u.scheme+'://'+u.host+(u.port>0?':'+u.port:'')+u.path,branch:h.push_events_branch_filter,push:h.push_events]}
def names=['security-gitlab-push-demo','security-gitleaks-demo']
def jobs=names.collect{n->def v=Jenkins.instance.getItemByFullName(n);def s=v?.definition?.script?:'';[name:n,exists:v!=null,disabled:v?.isDisabled(),lastBuild:v?.lastBuild?.number,lastResult:v?.lastBuild?.result?.toString(),building:v?.lastBuild?.building,definitionSha256:java.security.MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString(),callsFixedScanner:s.contains('run-clean.mjs'),hasGitOpsStage:s.contains('run-cd.mjs'),callsManagerHttp:s.contains('/api/run')||s.contains('/api/ci/'),hasGitLabTrigger:v?.triggers?.values()?.any{it.class.name.contains('GitLab')}]}
def creds=com.cloudbees.plugins.credentials.SystemCredentialsProvider.instance.credentials.findAll{it.id.startsWith('security-')}.collect{[id:it.id,type:it.class.simpleName]}
println(JsonOutput.toJson([hooks:hooks,jobs:jobs,credentialMetadata:creds,mutations:0]))
'''
x=p['script'](code)
remote=r'''
import pathlib,json,re
root=pathlib.Path('/var/lib/security-gitleaks');k=root/'.ssh/authorized_keys';lines=k.read_text().splitlines()
print(json.dumps({'jenkinsKeyCommands':[re.search(r'command="([^"]+)"',l).group(1)for l in lines if 'security-gitleaks-demo-ssh'in l],'existingProofWrapper':pathlib.Path('/usr/local/libexec/security-gitleaks-ci-proof.py').is_file(),'mutations':0}))
'''
x['ssh']=json.loads(p['m']['remote']('sudo -n python3 -',remote,20))
x['managerLocalCode']={'bind':'127.0.0.1:17862','currentProjectCatalog':list(json.loads(pathlib.Path('infra/security/manager-v2/sbom/projects.json').read_text())['projects']),'ciApiImplemented':False,'ciProjectGitleaksGrantPresent':False}
with pathlib.Path('evidence/2026-11-07/ci-standard-interface/live-preflight.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
