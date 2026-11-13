from pathlib import Path
import subprocess,json,shlex
O=Path(__file__).resolve().parent;old=json.loads((O.parent/'trivy-infra-repair/image-reference-graph.json').read_text());unknown=[r for r in old['records'] if r['classification']=='D'];repos={}
for r in unknown:
 for s in r['repoDigests']:
  host,rest=s.split('/',1);repo,digest=rest.split('@');
  if host!='core.harbor.domain':repos[repo]=host
code=r'''
import json,urllib.request,urllib.error,hashlib
repos=REPOS;out=[]
noProxy=urllib.request.build_opener(urllib.request.ProxyHandler({}));accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
for repo,host in repos.items():
 row={'repository':repo,'originalRegistry':host,'readEndpoint':'http://127.0.0.1:30050','tags':[],'manifests':[]}
 try:
  with noProxy.open('http://127.0.0.1:30050/v2/'+repo+'/tags/list',timeout=6) as res:body=json.load(res);row['tagStatus']=res.status;tags=body.get('tags') or []
  if len(tags)>150:raise ValueError('Bounded tag inventory exceeded; preserve all')
  for tag in tags:
   row['tags'].append(tag)
   try:
    req=urllib.request.Request('http://127.0.0.1:30050/v2/'+repo+'/manifests/'+tag,headers={'Accept':accept})
    with noProxy.open(req,timeout=6) as res:
     b=res.read(2*1024*1024);x=json.loads(b);row['manifests'].append({'tag':tag,'digest':res.headers.get('Docker-Content-Digest'),'bodySha256':'sha256:'+hashlib.sha256(b).hexdigest(),'mediaType':x.get('mediaType'),'children':x.get('manifests',[]),'config':x.get('config'),'layers':x.get('layers',[]),'subject':x.get('subject')})
   except Exception as e:row['manifests'].append({'tag':tag,'errorClass':type(e).__name__})
 except Exception as e:row['errorClass']=type(e).__name__;row['httpStatus']=getattr(e,'code',None)
 out.append(row)
print(json.dumps({'method':'GET_ONLY','repositoryGraph':out,'writes':0}))
'''.replace('REPOS',repr(repos))
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=120);assert p.returncode==0;data=json.loads(p.stdout);(O/'local-registry-graph.json').write_text(json.dumps(data,indent=2)+'\n');print(json.dumps({'repositories':len(data['repositoryGraph']),'tags':sum(len(x['tags']) for x in data['repositoryGraph']),'errors':[{'repo':x['repository'],'error':x.get('errorClass')} for x in data['repositoryGraph'] if x.get('errorClass')],'mutations':0}))
