"""Render verified, timestamped read-only snapshots into the existing page; no network."""
import datetime,hashlib,html,json
from pathlib import Path
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
source=OUT/'read-only-sources.json'
links=OUT/'links-observability.json'
sec=OUT/'security-navigation.json'
j,h=json.loads(source.read_text()).values()
n=json.loads(links.read_text());s=json.loads(sec.read_text())
stamp=h['at']
def instant(ms):return datetime.datetime.fromtimestamp(ms/1000,datetime.timezone.utc).isoformat()
def link(key,label=None):
 r=n['links'][key]
 return {'label':label or key,'url':r['url'],'http':r['http'],
         'note':'HTTP reachable; authentication may be required'}
def card(title,state,observed,rows,urls=(),note=''):
 return {'title':title,'classification':state,'observedAt':observed,'rows':rows,'links':list(urls),'note':note}
digest=h['deployment']['images'][0]
build=j['build270'];candidate=j['candidateBuild2'];gate=j['sourceGate']
rows=[
card('GitLab · 项目与构建提交','HISTORICAL',instant(build['timestamp']),[
 ['项目','root/petclinic-platform'],['构建实际检出的 Commit',build['commit']],
 ['GitLab Push Trigger',s['triggers'][0]['type']],['自动触发验收','UNAVAILABLE · 本次未发送 Push；#270 为 UserIdCause']],
 [link('gitlab','GitLab 项目'),link('commit','查看 #270 对应提交')],
 'SCM 当前固定到审计提交，非跟踪 main。项目 API 匿名返回 404；不据此推断项目不存在或自动触发已通过。'),
card('Jenkins · 最近主作业构建','HISTORICAL',instant(build['timestamp']),[
 ['作业','petclinic-ci #'+str(build['number'])],['结果',build['result']],['定义',j['job']['scriptPath']],
 ['本次只读查询确认的最近构建','#'+str(j['job']['lastBuild']['number'])],
 ['构建类型',j['provenance']['buildType']]], [link('jenkins','打开 Jenkins #270')],
 '这是已完成的安全审计构建，不是本轮新发布；其记录不能替代当前生产镜像的构建与晋升证明。'),
card('Security Gate · 已归档实际结果','HISTORICAL',s['summary']['recorded_at'],[
 ['Source Gate 原始 status',gate['status']],['Source Gate 阻断项',str(len(gate['sourceScan']['blockingFindings']))],
 ['V1 Summary Gitleaks status',s['summary']['gitleaks_status']],
 ['V1 Summary Gitleaks blocking count',str(s['summary']['gitleaks_findings'])],
 ['模式 / Profile',s['summary']['securityMode']+' / '+s['summary']['securityProfile']]],
 [{'label':'原始 V1 Summary（需 Jenkins 登录）','url':n['links']['jenkins']['url']+'artifact/.devsecops/security-summary.json','http':403},
 {'label':'原始 Source Gate（需 Jenkins 登录）','url':n['links']['jenkins']['url']+'artifact/.devsecops/source-gate.json','http':403}],
 '数值与字段语义保留原样；下方 Gitleaks Clean/Finding 是独立受控运行，不能拼成本审计构建。'),
card('Harbor · 候选镜像构建关联','HISTORICAL',instant(candidate['timestamp']),[
 ['真实构建','petclinic-candidate-build #2 · '+candidate['result']],
 ['源 Commit',candidate['commit']],['候选镜像',j['buildProof']['candidateImage']],
 ['#270 build-attestation-verification',j['buildProof']['status']]],
 [{'label':'候选镜像真实构建 #2','url':'http://jenkins.devops.local/job/petclinic-candidate-build/2/','http':403},
 link('harbor','Harbor 镜像仓库')],
 '候选镜像与运行镜像不同。当前 Harbor artifact 匿名 API 返回 401；不能声称已实时核验 Registry 内容。'),
card('Argo CD · GitOps 部署快照','HISTORICAL',stamp,[
 ['同步 / 健康',h['argo']['sync']+' / '+h['argo']['health']],['GitOps Revision',h['argo']['revision']],
 ['清单路径 / 分支',h['argo']['source']['path']+' / '+h['argo']['source']['targetRevision']],
 ['最近部署时间',h['argo']['history'][-1]['deployedAt']]],
 [{'label':'Argo CD 首页（选择 petclinic）','url':'http://argocd.devops.local/','http':200}],
 '只读 Kubernetes Application 对象。首页 HTTP 200；原应用深链返回 404，改用既有首页，未修改 Argo CD。'),
card('Kubernetes · PetClinic 部署快照','HISTORICAL',stamp,[
 ['Ready / Desired',str(h['deployment']['ready'])+' / '+str(h['deployment']['desired'])],
 ['Node Ready',' · '.join(v['name']+'='+v['ready'] for v in h['nodes'])],
 ['Pod 分布',' · '.join(v['node'] for v in h['pods'])],
 ['运行镜像 Digest',digest],['业务 HTTP',str(h['http']['status'])]],
 [link('petclinic','打开 PetClinic')],
 '页面不连接 Kubernetes API。以上为采集时快照；刷新页面不会重查集群，也不会部署。'),
card('Grafana / Loki · 可观测性快照','HISTORICAL',stamp,[
 ['已部署 Grafana UID',n['observability']['grafanaProvisionedDashboard']['uid']],
 ['Prometheus PetClinic UP',str(sum(t['up']=='1' for t in n['observability']['prometheus']['targets']))+' / '+str(len(n['observability']['prometheus']['targets']))],
 ['Loki 查询结果',n['observability']['loki']['status']+' · '+str(n['observability']['loki']['streams'])+' stream'],
 ['Loki 查询','{namespace="petclinic"} · 最近 5 分钟 · limit=1']],
 [link('grafana','Grafana 现有安全看板'),
 {'label':'Grafana Explore（选择 Loki）','url':'http://grafana.devops.local/explore','http':302}],
 'Loki 原始日志不进入页面。Grafana 导航需要登录；未声称已验证登录后的面板查询。')
]
snapshot={'kind':'PetClinicPipelineOverviewSnapshot','classification':'HISTORICAL',
'capturedAt':stamp,'cards':rows,
'limits':[
 'LIVE=无。页面展示真实历史归档与带时间的当前状态快照，不冒充实时跨系统查询。',
 '已证明：GitLab Commit → 候选构建 #2 → 候选镜像 → #270 安全审计/构建证明校验。',
 '已证明：GitOps Revision → Argo CD Synced/Healthy → 当前 PetClinic 3/3；两段证据不是同一次端到端生产发布。',
 '未验证：本次 GitLab Push 自动触发、候选镜像晋升为当前运行镜像、完整同次发布链、Harbor 登录后的 artifact 内容。',
 'Gitleaks Clean #2 / Finding #3 的 Jenkins 门禁演示独立保留；Production Manager NOT_ACTIVE，Canonical Runtime 14/16。'],
'sources':[{'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [source,links,sec]],
'releaseCount':0,'rolloutCount':0}
with (OUT/'pipeline-snapshot.json').open('x') as f:json.dump(snapshot,f,indent=2,ensure_ascii=False)
E=lambda v:html.escape(str(v),quote=True)
section=['<!-- PETCLINIC_PIPELINE_OVERVIEW_BEGIN -->','<section id="pipeline-overview">',
'<div class="section-heading"><div><span class="eyebrow">PETCLINIC DEVSECOPS</span><h2>PetClinic Pipeline Overview</h2></div><span class="tag replay">HISTORICAL · 只读快照</span></div>',
'<p class="muted">采集时间：<time datetime="'+E(stamp)+'">'+E(datetime.datetime.fromisoformat(stamp).astimezone(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S +08:00'))+'</time>。刷新只重新读取本地记录，不触发扫描、构建或生产查询。</p>',
'<p class="muted">GitLab → Jenkins / Security Gate → Harbor 候选镜像 · GitOps → Argo CD → Kubernetes。下列分段证据不代表同轮生产发布。</p>',
'<div class="consumer-grid">']
for r in rows:
 section+=['<article class="consumer"><div class="card-top"><h3>'+E(r['title'])+'</h3><span class="tag replay">'+E(r['classification'])+'</span></div>',
 '<p>数据时点：<time datetime="'+E(r['observedAt'])+'">'+E(r['observedAt'])+'</time></p>']
 section+=['<div class="card-row"><span>'+E(k)+'</span><b>'+E(v)+'</b></div>' for k,v in r['rows']]
 section+=['<p>'+E(r['note'])+'</p>']
 section+=['<p><a href="'+E(l['url'])+'">'+E(l['label'])+'</a> · HTTP '+E(l['http'])+'（检查于本次采集）</p>' for l in r['links']]
 section+=['</article>']
section+=['</div>','<details><summary>链路证明范围与尚未验证部分</summary>']
section+=['<p>'+E(t)+'</p>' for t in snapshot['limits']]
section+=['<p class="source-path">'+E(v['path'])+' · SHA256 '+E(v['sha256'])+'</p>' for v in snapshot['sources']]
section+=['</details></section>','<!-- PETCLINIC_PIPELINE_OVERVIEW_END -->']
page=ROOT/'infra/security/manager-v2/view/index.html'
v=page.read_text()
assert 'PETCLINIC_PIPELINE_OVERVIEW_BEGIN' not in v
needle='<section id="live-validation">'
assert v.count(needle)==1
v=v.replace(needle,'\n'.join(section)+'\n'+needle)
v=v.replace('<nav><a class="active" href="#overview">','<nav><a href="#pipeline-overview">00 &nbsp; 流水线总览</a><a class="active" href="#overview">')
page.write_text(v)
print('Rendered',len(rows),'sourced cards; no LIVE claims, no new backend or server restart.')
