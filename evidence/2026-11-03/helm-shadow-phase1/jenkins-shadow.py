"""Dedicated non-release Helm validation job only; production job/config and GitOps untouched."""
from pathlib import Path
import json,subprocess,shlex,sys,hashlib,tarfile,io,urllib.parse,base64,os
O=Path(__file__).resolve().parent;R=O.parents[2];sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];JOB='petclinic-helm-shadow-20261103';WORK='/var/jenkins_home/workspace/'+JOB
sha=lambda b:hashlib.sha256(b).hexdigest()
def api(path,method='GET',body=None,kind=None):
 data={'path':path,'method':method,'timeout':90000}
 if body is not None:data['body']=body
 if kind:data['type']=kind
 p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)],input=json.dumps(data),capture_output=True,text=True,timeout=110);assert p.returncode==0,'Trusted Jenkins access failed';r=json.loads(p.stdout);assert r['status']<400,'Jenkins status '+str(r['status']);return r
def groovy(script):return api('/scriptText','POST',urllib.parse.urlencode({'script':script}),'application/x-www-form-urlencoded')
mode=sys.argv[1]
if mode in ['prepare','update']:
 files=[]
 for prefix in ['charts/petclinic','infra/helm']:
  files += [p for p in (R/prefix).rglob('*') if p.is_file()]
 for p in ['Jenkinsfile','Jenkinsfile.security-audit','Jenkinsfile.candidate-build','Jenkinsfile.helm-shadow','vars/helmShadow.groovy','infra/argocd/petclinic-helm-candidate.yaml','infra/security/promotion/contract.mjs','infra/security/production-baseline.json']:
  files.append(R/p)
 manifest={'kind':'HELM_SHADOW_REVIEW_BUNDLE','productionGitOpsRevision':'340ef4b8c74e3c2a5820da8d98b0f134283bb8d9','files':{str(p.relative_to(R)):sha(p.read_bytes()) for p in sorted(set(files))}}
 data=(json.dumps(manifest,indent=2)+'\n').encode();manifestSha=sha(data);(O/'review-bundle-manifest.json').write_bytes(data)
 archive=O/'review-bundle.tar.gz'
 with tarfile.open(archive,'w:gz') as tar:
  for p in sorted(set(files)):tar.add(p,arcname=str(p.relative_to(R)))
  meta=tarfile.TarInfo('.helm-review-manifest.json');meta.size=len(data);tar.addfile(meta,io.BytesIO(data))
  p=R/'.tools/helm-downloads/helm-v3.22.1-linux-arm64.tar.gz';tar.add(p,arcname=str(p.relative_to(R)))
 # Dedicated workspace only; no production workspace/credentials/config touched.
 command='sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- sh -c '+shlex.quote('umask 077; mkdir -p '+shlex.quote(WORK)+'; tar -xz -C '+shlex.quote(WORK))
 with archive.open('rb') as source:p=subprocess.run(S+[command],stdin=source,capture_output=True,timeout=90)
 assert p.returncode==0,'Dedicated workspace transfer failed'
 script=(R/'Jenkinsfile.helm-shadow').read_text().replace('node infra/helm/verify-review-bundle.mjs\'','node infra/helm/verify-review-bundle.mjs '+manifestSha+"'")
 payload=base64.b64encode(script.encode()).decode()
 gs='''import groovy.json.JsonOutput
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import hudson.model.*
def prod=Jenkins.instance.getItemByFullName('petclinic-ci');assert prod.lastBuild.number==270 && prod.lastBuild.result.toString()=='SUCCESS'
def name=JOBNAME
def job=Jenkins.instance.getItemByFullName(name)
if(job==null){job=Jenkins.instance.createProject(WorkflowJob.class,name)}else{assert job.fullName=='petclinic-helm-shadow-20261103' && !job.building:'Dedicated job must be idle'}
job.definition=new CpsFlowDefinition(new String(SCRIPT.decodeBase64(),'UTF-8'),true)
job.addProperty(new ParametersDefinitionProperty(new BooleanParameterDefinition('HELM_ENABLED',false,'Shadow only'),new ChoiceParameterDefinition('PROMOTION_ACTION',['audit-only'] as String[],'No deployment')))
job.description='HELM PHASE1 / VALIDATION_ONLY / no GitOps push, Kubernetes mutation, approval or release. Review manifest '+MANIFEST
job.save()
println(JsonOutput.toJson([job:name,productionBuild:prod.lastBuild.number,manifestSha256:MANIFEST,sandbox:true,productionJobChanged:false]))
'''.replace('JOBNAME',json.dumps(JOB)).replace('SCRIPT',json.dumps(payload)).replace('MANIFEST',json.dumps(manifestSha))
 result=groovy(gs);x=json.loads(result['body'].split('\n',1)[0]);(O/('jenkins-shadow-created.json' if mode=='prepare' else 'jenkins-shadow-updated.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
elif mode=='lint':
 results=[]
 for name in ['Jenkinsfile.security-audit','Jenkinsfile.helm-shadow']:
  r=api('/pipeline-model-converter/validate','POST',urllib.parse.urlencode({'jenkinsfile':(R/name).read_text()}),'application/x-www-form-urlencoded')
  results.append({'file':name,'result':r['body']})
 (O/'jenkins-native-lint.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
 assert all('successfully validated' in r['result'] for r in results),'Jenkins Declarative validation failed'
elif mode in ['off','on']:
 r=api('/job/'+JOB+'/buildWithParameters','POST',urllib.parse.urlencode({'HELM_ENABLED':'true' if mode=='on' else 'false','PROMOTION_ACTION':'audit-only'}),'application/x-www-form-urlencoded');(O/('jenkins-'+mode+'-queue.json')).write_text(json.dumps({'status':r['status'],'queue':r.get('location')},indent=2)+'\n');print(json.dumps({'mode':mode,'status':r['status'],'queue':r.get('location')}))
elif mode=='status':
 x=json.loads(api('/job/'+JOB+'/lastBuild/api/json?tree=number,building,result,url,artifacts[relativePath],actions[parameters[name,value]]')['body']);(O/('jenkins-build-'+str(x['number'])+'.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
elif mode=='logs':
 n=int(sys.argv[2]);r=api('/job/'+JOB+'/'+str(n)+'/consoleText');(O/('jenkins-build-'+str(n)+'.log')).write_text(r['body']);print(r['body'][-7000:])
elif mode=='artifacts':
 n=int(sys.argv[2]);build=json.loads(api('/job/'+JOB+'/'+str(n)+'/api/json?tree=number,result,artifacts[relativePath]')['body']);out=O/('jenkins-artifacts-'+str(n));out.mkdir(exist_ok=True);entries={}
 for a in build['artifacts']:
  name=a['relativePath'];assert '..' not in Path(name).parts
  r=api('/job/'+JOB+'/'+str(n)+'/artifact/'+urllib.parse.quote(name));p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(r['body']);entries[name]=sha(p.read_bytes())
 (O/('jenkins-artifact-hashes-'+str(n)+'.json')).write_text(json.dumps(entries,indent=2)+'\n');print(json.dumps({'build':n,'result':build['result'],'artifactHashes':entries}))
else:raise SystemExit('Unknown mode')
