"""Narrow final read-only acceptance of same-run commits, restoration and production."""
import json
import runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
plan=json.loads((OUT/'prepared.json').read_text())
observed=[json.loads((OUT/(s+'.json')).read_text()) for s in ['baseline','updated','restored']]
assert all(v['verified'] for v in observed)
assert len({v['configMap']['uid'] for v in observed})==1
assert len({v['configMap']['resourceVersion'] for v in observed})==3
assert [v['configMap']['data']['demo-stage'] for v in observed]==['baseline','updated','baseline']
assert plan['commits']['baseline']['tree']==plan['commits']['restored']['tree']
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import java.security.MessageDigest
def hash={byte[] v->MessageDigest.getInstance('SHA-256').digest(v).encodeHex().toString()}
def shas=@SHAS@
def proofs=shas.collect{sha->
 def c=api('/projects/12/repository/commits/'+sha)
 def d=api('/projects/12/repository/commits/'+sha+'/diff')
 assert d.size()==1 && d[0].new_path=='infra/devops-lab/gitops-demo/configmap.yaml'
 [commit:c.id,parents:c.parent_ids,title:c.title,message:c.message,committedAt:c.committed_date,paths:d.collect{it.new_path}]
}
assert proofs[0].parents==[] && proofs[1].parents==[shas[0]] && proofs[2].parents==[shas[1]]
assert proofs[2].message.contains('This reverts commit '+shas[1])
def branch=api('/projects/12/repository/branches/security-demo%2Fgitops-20261105')
def main=api('/projects/12/repository/branches/main')
assert branch.commit.id==shas[2] && main.commit.id=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
assert j.lastBuild.number==270 && !j.isBuilding() && j.lastBuild.result.toString()=='SUCCESS'
def sf=new File(j.lastBuild.artifactsDir,'.devsecops/security-summary.json')
assert hash(sf.bytes)=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
assert hash(j.configFile.file.bytes)=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
def pipelines=api('/projects/12/pipelines?ref=security-demo%2Fgitops-20261105&per_page=10').collect{[id:it.id,status:it.status,sha:it.sha]}
assert pipelines.every{it.status=='skipped'}
println(JsonOutput.toJson([commitProofs:proofs,branchHead:branch.commit.id,productionMain:main.commit.id,pipelines:pipelines,
 productionJenkins:[number:270,result:'SUCCESS',definitionUnchanged:true,v1SummaryUnchanged:true]]))
'''.replace('@SHAS@',json.dumps([plan['commits'][s]['commit'] for s in ['baseline','updated','restored']]))
gitlab=p['script'](code)
host=r'''
import json,subprocess,datetime,hashlib,urllib.request,urllib.error,os
def k(a):return json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=10))
d=k(['-n','petclinic','get','deployment','petclinic','-o','json'])
a=k(['-n','argocd','get','application','petclinic','-o','json'])
demo=k(['-n','argocd','get','application','petclinic-gitops-demo','-o','json'])
cm=k(['-n','devsecops-test','get','configmap','petclinic-gitops-demo','-o','json'])
nodes=k(['get','nodes','-o','json'])
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=5) as r:http=r.status
except urllib.error.HTTPError as e:http=e.code
except (OSError,urllib.error.URLError):http='UNAVAILABLE'
sha=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'production':{'uid':d['metadata']['uid'],'generation':d['metadata']['generation'],'specSha256':sha(d['spec']),
 'ready':d['status'].get('readyReplicas',0),'desired':d['spec']['replicas'],'image':[v['image'] for v in d['spec']['template']['spec']['containers']],
 'argoRevision':a['status']['sync']['revision'],'argoSync':a['status']['sync']['status'],'argoHealth':a['status']['health']['status'],'argoSpecSha256':sha(a['spec']),
 'nodes':{v['metadata']['name']:next(c['status'] for c in v['status']['conditions'] if c['type']=='Ready') for v in nodes['items']},'http':http,'dockerSocketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o')},
 'demo':{'revision':demo['status']['sync']['revision'],'sync':demo['status']['sync']['status'],'health':demo['status']['health']['status'],'history':[{'revision':v['revision'],'deployedAt':v['deployedAt']} for v in demo['status'].get('history',[])],
 'resourceCount':len(demo['status'].get('resources',[])),'configMapValue':cm['data']['demo-stage'],'configMapUid':cm['metadata']['uid'],
 'namespacePodCount':len(k(['-n','devsecops-test','get','pods','-o','json'])['items'])}}))
'''
state=json.loads(p['m']['remote']('sudo -n python3 -',host,55))
before=json.loads((OUT/'preflight.json').read_text())['host']['production']
after=state['production']
for key in ['uid','generation','specSha256','image','argoRevision','argoSpecSha256','dockerSocketMode']:assert after[key]==before[key],key
assert after['ready']==after['desired']==3 and after['http']==200 and after['argoSync']=='Synced' and after['argoHealth']=='Healthy'
assert all(v=='True' for v in after['nodes'].values())
assert state['demo']['configMapValue']=='baseline' and state['demo']['revision']==plan['commits']['restored']['commit']
assert state['demo']['resourceCount']==1 and state['demo']['namespacePodCount']==0
result={'gitlab':gitlab,'host':state,'configMapSameUid':True,'threeDistinctResourceVersions':True,
 'verdict':{'GITOPS_DEMO_REAL_CHANGE':'VERIFIED','ARGOCD_SYNC':'VERIFIED','KUBERNETES_STATE_CHANGE':'VERIFIED','GITOPS_RESTORE':'VERIFIED','PRODUCTION_PETCLINIC_UNCHANGED':'YES'},
 'actualGitPushes':3,'configMapDirectWrites':0,'productionRelease':False,'productionRollout':False}
with (OUT/'verified.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
