"""Verify read-only snapshots and render one existing-page card. No production writes."""
import json,base64,hashlib,html,yaml
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
h=json.loads((OUT/'host.json').read_text());s=json.loads((OUT/'sources.json').read_text())
candidate='sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55'
revision=h['argo']['sync']['revision'];assert revision==s['gitops']['head']
assert h['argo']['sync']['status']=='Synced' and h['argo']['health']['status']=='Healthy'
assert h['argo']['lastSyncRevision']==revision and h['argo']['operationPhase']=='Succeeded'
f=next(x for x in s['gitops']['files'] if x['revision']==revision)
b=base64.b64decode(f['contentBase64']);assert hashlib.sha256(b).hexdigest()==f['sha256']
assert not any(x['name'] in ['kustomization.yaml','kustomization.yml','Kustomization','Chart.yaml'] for x in f['tree'])
docs=[d for d in yaml.safe_load_all(b) if d and d.get('kind')=='Deployment' and d['metadata'].get('namespace')=='petclinic' and d['metadata']['name']=='petclinic']
assert len(docs)==1
image=next(c['image'] for c in docs[0]['spec']['template']['spec']['containers'] if c['name']=='petclinic')
actual=next(c['image'] for c in h['deployment']['containers'] if c['name']=='petclinic')
assert image==actual and '@sha256:' in image
running=image.split('@')[1];assert candidate!=running
artifacts={a['digest']:a for a in s['harbor']['artifacts']};manifests=s['harbor']['manifests']
assert artifacts[candidate]['http']==artifacts[running]['http']==200
assert s['harbor']['rawManifestDigestsVerified'] is True and s['harbor']['pullOnly'] is True
assert '0.10.0-ci-1000002' in artifacts[candidate]['tags']
assert 'image.index' in manifests[running]['mediaType'] and 'image.index' in manifests[candidate]['mediaType']
platforms=lambda dg:{p['platform']['architecture']:p['digest'] for p in manifests[dg]['manifests'] if p.get('platform',{}).get('os')=='linux' and p['platform'].get('architecture') in ['amd64','arm64']}
currentPlatforms=platforms(running);candidatePlatforms=platforms(candidate)
assert set(currentPlatforms)==set(candidatePlatforms)=={'arm64','amd64'}
assert not set(currentPlatforms.values())&set(candidatePlatforms.values())
assert len(h['pods'])==3 and h['deployment']['ready']==h['deployment']['desired']==3
assert h['deployment']['observedGeneration']==h['deployment']['generation']
rows=[]
for p in h['pods']:
 assert p['phase']=='Running' and p['deletionTimestamp'] is None
 c=next(c for c in p['containers'] if c['name']=='petclinic');status=c['running']
 assert c['desiredImage']==image and status['ready'] is True
 arch=h['nodes'][p['node']]['arch'];child=currentPlatforms[arch];config=manifests[child]['config']['digest']
 assert status['imageID'].endswith('@'+running), 'Expected actual Index Image ID, do not infer from Pod spec'
 assert status['image']==config, 'Running config must match verified platform manifest'
 rows.append({'pod':p['name'],'node':p['node'],'architecture':arch,'imageID':status['imageID'],'reportedDigestType':'OCI_INDEX',
 'platformManifestDigest':child,'runtimeConfigDigest':status['image'],'configMatchesPlatformManifest':True,'ready':True,'desiredVsRunning':'MATCHED'})
assert h['http']==200 and len(h['endpoints'])==3 and all(x['conditions']['ready'] for x in h['endpoints'])
assert all(n['ready']=='True' for n in h['nodes'].values())
assert s['productionJob']['latestBuild']==270 and s['productionJob']['result']=='SUCCESS'
assert s['productionJob']['definitionSha256']=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
assert s['productionJob']['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
proof={'candidateTag':'petclinic/petclinic:0.10.0-ci-1000002','candidateDigest':candidate,'gitopsRevision':revision,
 'gitopsHead':s['gitops']['head'],'gitopsDesiredImage':image,'gitopsFileSha256':f['sha256'],'argoSync':'Synced','argoHealth':'Healthy',
 'deploymentImage':actual,'pods':rows,'candidatePlatforms':candidatePlatforms,'runningPlatforms':currentPlatforms,
 'comparison':'NOT_DEPLOYED','desiredVsRunning':'MATCHED','reason':'Current GitOps and Deployment reference a different OCI Index; all three actual Pod Image IDs and architecture-specific config digests match the current image, not candidate.',
 'sourceClass':'LIVE_QUERY_SNAPSHOT','queryTimes':{'host':h['observedAt'],'gitopsHarbor':s['observedAt']},
 'historicalRelease':{'source':'petclinic-ci #270 archived Read-Only-Release-Verification.txt','exitCode':0,'reusedAsCurrentEvidence':False},
 'productionHealth':'HEALTHY','releaseCount':0,'rolloutCount':0,'productionSecurityManager':'NOT_ACTIVE','canonicalRuntime':'14/16'}
assert 'exit_code=0' in s['historicalReleaseVerification']['content']
with (OUT/'verified.json').open('x') as f:json.dump(proof,f,indent=2)
E=lambda v:html.escape(str(v),quote=True)
sourceTime=s['observedAt'];hostTime=h['observedAt']
fields=[('Harbor Candidate Tag',proof['candidateTag'],sourceTime),('Candidate OCI Index Digest',candidate,sourceTime),
 ('GitOps 仓库 / 文件','root/petclinic-platform · main · k8s/production/petclinic.yaml',sourceTime),
 ('GitOps 当前 HEAD / Desired Revision',s['gitops']['head'],sourceTime),('GitOps Desired Image',image,sourceTime),
 ('Argo CD Synced Revision',revision,hostTime),('Argo CD Sync / Health','Synced / Healthy',hostTime),
 ('Deployment Image',actual,hostTime),('Ready / Endpoints / HTTP','3/3 · 3 Ready Endpoints · HTTP 200',hostTime),
 ('Desired vs Running','MATCHED · GitOps / Deployment / 三个实际 Image ID 一致',hostTime),
 ('Candidate vs Running','NOT_DEPLOYED · 候选 Index 未被当前 GitOps / Deployment / Pod 引用',hostTime)]
card='''<!-- CANDIDATE_RUNNING_BEGIN -->
<article id="candidate-running" class="consumer">
<div class="card-top"><h3>Candidate vs Running Deployment</h3><span class="tag replay">NOT_DEPLOYED</span></div>
<p>候选镜像尚未部署；当前 GitOps 期望与 Kubernetes 实际运行一致。Argo CD Healthy 仅描述当前部署，不能证明候选镜像已上线。</p>
<p>以下为本轮 LIVE 只读查询形成的有时间标记的快照；刷新页面只读取本地记录，不重查生产，不触发 Sync 或 Rollout。归档历史为 HISTORICAL。</p>
<table><thead><tr><th>追溯字段</th><th>真实值</th><th>来源 / 采集时间（UTC）</th></tr></thead><tbody>
'''
for k,v,t in fields:card+='<tr><td>'+E(k)+'</td><td>'+E(v)+'</td><td>LIVE 查询快照<br>'+E(t)+'</td></tr>\n'
card+='</tbody></table><h4>Pod 实际运行记录</h4>\n'
for row in rows:
 card+='<div class="card-row"><span>'+E(row['pod'])+'<br>'+E(row['node'])+' / '+E(row['architecture'])+' · Ready</span><b>'+E(row['imageID'])+'</b></div>\n'
card+='<p>以上三个 Image ID 的来源：LIVE Kubernetes 查询快照 · '+E(hostTime)+'。Image ID 报告的是 OCI Index；镜像仓库别名虽不同，Digest 相同。</p>\n'
card+='<details><summary>多架构 Digest 对照（避免将 Index 与平台子 Manifest 误判）</summary>\n'
for arch in ['amd64','arm64']:
 card+='<p>'+arch+' · Candidate Manifest: '+E(candidatePlatforms[arch])+'<br>Running Manifest: '+E(currentPlatforms[arch])+'</p>\n'
card+='<p>当前三个 Pod 位于 arm64 节点，其运行配置 Digest 为 '+E(rows[0]['runtimeConfigDigest'])+'，与当前 ARM64 Manifest 的 config.digest 相同。Index 和平台 Manifest 原始响应的 SHA256 已核验；未知架构的 attestation 条目未被当作运行镜像。</p></details>\n'
revUrl='http://gitlab.devops.local/root/petclinic-platform/-/blob/'+revision+'/k8s/production/petclinic.yaml'
base='http://harbor.devops.local/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'
links=[(base+candidate,'Harbor 候选精确 Digest（需登录）'),(base+running,'Harbor 当前运行镜像（需登录）'),
 (revUrl,'GitOps 已同步提交中的原始 YAML'),('http://argocd.devops.local/','Argo CD（选择 petclinic）'),
 ('http://petclinic.devops.local/','PetClinic'),
 ('http://jenkins.devops.local/job/petclinic-ci/270/artifact/.devsecops/gates/Read-Only-Release-Verification.txt','HISTORICAL · #270 只读部署验收归档')]
card+='<p>'+' · '.join('<a href="'+E(u)+'">'+E(label)+'</a>' for u,label in links)+'</p>\n'
card+='<p>历史归档 exit_code=0 仅供追溯，不代替本轮当前状态；未将安全演示 #4 或候选构建 #2 当作一次生产发布。未执行发布；Release=0 / Rollout=0。</p>\n'
card+='<p class="source-path">evidence/2026-11-05/candidate-running/verified.json · SHA256 '+hashlib.sha256((OUT/'verified.json').read_bytes()).hexdigest()+'</p>\n</article>\n<!-- CANDIDATE_RUNNING_END -->\n'
page=ROOT/'infra/security/manager-v2/view/index.html';text=page.read_text()
assert '<!-- CANDIDATE_RUNNING_BEGIN -->' not in text and '<!-- BUILD_HARBOR_LINK_BEGIN -->' in text
page.write_text(text.replace('<!-- BUILD_HARBOR_LINK_BEGIN -->',card+'<!-- BUILD_HARBOR_LINK_BEGIN -->',1))
print(json.dumps({'comparison':proof['comparison'],'gitopsRevision':revision,'desired':image,'running':actual,'podImageIds':[p['imageID'] for p in rows],'production':'HEALTHY'}))
