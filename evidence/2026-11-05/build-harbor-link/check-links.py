"""Bounded real HTTP verification; no build APIs, scans or writes."""
import json,runpy,shlex,datetime,urllib.request,concurrent.futures,subprocess,hashlib
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
proof=json.loads((OUT/'verified.json').read_text())
base='http://security.devops.local:17862';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with op.open(base+'/',timeout=6) as r:status=r.status;body=r.read()
with op.open(base+'/',timeout=6) as r:status2=r.status;body2=r.read()
assert status==status2==200 and body==body2
card=body.decode().split('<!-- BUILD_HARBOR_LINK_BEGIN -->')[1].split('<!-- BUILD_HARBOR_LINK_END -->')[0]
for v in [proof['commit'],proof['securityBuild']['url'],proof['imageBuild']['url'],proof['harbor']['tag'],proof['harbor']['digest'],'HISTORICAL','LIVE 查询快照']:assert v in card
assert 'PRIVATE KEY-----' not in card and 'PRIVATE-TOKEN' not in card
paths=['/job/petclinic-ci/270/api/json','/job/petclinic-candidate-build/2/api/json',
 '/job/petclinic-ci/270/artifact/.devsecops/security-summary.json','/job/petclinic-ci/270/artifact/.devsecops/build-attestation-verification.json']
jenkins=[]
for path in paths:
 r=json.loads(p['m']['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(p['NODE']),json.dumps({'path':path,'method':'GET','timeout':10000}),25))
 assert r['status']==200
 data=json.loads(r['body'])
 if path.endswith('/api/json'):assert data['result']=='SUCCESS'
 if path.endswith('security-summary.json'):assert data['source']==proof['commit'] and data['auditTargetImage'].endswith(proof['harbor']['digest'])
 jenkins.append({'url':'http://jenkins.devops.local'+path,'authenticatedHttp':r['status']})
commit=p['script'](p['PREFIX']+"def c=api('/projects/12/repository/commits/"+proof['commit']+"');println(JsonOutput.toJson([id:c.id,webUrl:c.web_url]))")
assert commit['id']==proof['commit']
urls={'gitlabCommit':commit['webUrl'].replace('http://gitlab-578fd9dcbb-rhbx8','http://gitlab.devops.local'),
 'harbor':proof['harbor']['uiUrl'],'harborExactArtifact':proof['harbor']['apiUrl']}
def check(kv):
 name,url=kv;r=subprocess.run(['curl','--noproxy','*','-4','--connect-timeout','3','--max-time','5','-sS','-o','/dev/null','-w','%{http_code}',url],capture_output=True,text=True,timeout=7)
 return name,{'url':url,'http':int(r.stdout) if r.stdout.isdigit() else None,'curlExit':r.returncode}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:nav=dict(ex.map(check,urls.items()))
assert all(v['curlExit']==0 for v in nav.values())
assert nav['harbor']['http']==200
# Anonymous private artifact 401 and GitLab login redirect are expected; authenticated contents are separately verified.
assert nav['harborExactArtifact']['http'] in [200,401]
assert nav['gitlabCommit']['http'] in [200,302]
res={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pageUrl':base+'/#pipeline-overview',
 'pageHttp':status,'refreshHttp':status2,'pageSha256':hashlib.sha256(body).hexdigest(),'associationVisible':True,
 'jenkins':jenkins,'gitlabCommitAuthenticatedRead':commit,'navigation':nav,'harborAuthenticatedArtifactHttp':proof['harbor']['http'],
 'browserClick':'NOT_TESTED','productionRelease':False,'productionRollout':False}
with (OUT/'http-acceptance.json').open('x') as f:json.dump(res,f,indent=2)
print(json.dumps(res))
