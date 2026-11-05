"""Render the authorized read-only fallback in the existing Pipeline Overview."""
import difflib
import hashlib
import html
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
source = OUT / 'observation.json'
v = json.loads(source.read_text())
p = v['production']
E = lambda s: html.escape(str(s), quote=True)
def row(label, value):
    return '<div class="card-row"><span>'+E(label)+'</span><b>'+E(value)+'</b></div>'

rev = p['argo']['revision']
links = {
    'Argo CD：选择 petclinic，查看 SYNC STATUS / APP HEALTH / HISTORY': 'http://argocd.devops.local/',
    'GitLab：查看 Argo 已同步 Revision 的原始 Deployment': 'http://gitlab.devops.local/root/petclinic-platform/-/blob/'+rev+'/k8s/production/petclinic.yaml',
    'PetClinic：实际打开业务页面': 'http://petclinic.devops.local/',
    'Grafana：已有安全看板（登录后查看）': 'http://grafana.devops.local/d/devsecops-control',
    'Grafana Explore：选择 Loki 查看 PetClinic 日志': 'http://grafana.devops.local/explore',
}
lines = ['<!-- GITOPS_DEMO_RESULT_BEGIN -->',
 '<article id="gitops-demo-result" class="consumer" aria-labelledby="gitops-demo-title">',
 '<div class="card-top"><h3 id="gitops-demo-title">GitOps Demo Result · 状态查看与排障</h3><span class="tag warn">REAL CHANGE · INCOMPLETE</span></div>',
 '<p>本轮交付只读查看入口，未执行新的 GitOps 变更或恢复。现有非生产 devops-tls-lab / rollouts-lab 均跟踪生产仓库 main；本轮禁止推送该分支。没有已接通获准测试分支的 Application，不能用直接 kubectl 修改冒充 GitOps。</p>',
 '<p class="muted">HISTORICAL · 本轮真实 Kubernetes GET 快照：<time>'+E(v['observedAt'])+'</time>。不是实时订阅；刷新只重新读取本地记录。下方链接可进入原系统查看当前状态。</p>',
 row('本轮演示对象 / 新 Git Commit', 'NONE · 未选择可授权写入的独立对象 / NONE'),
 row('生产 GitOps 已同步 Revision',rev),
 row('Argo CD / Kubernetes','%s / %s · Ready %s/%s · Ready Endpoints %s · HTTP %s'%(p['argo']['sync'],p['argo']['health'],p['ready'],p['desired'],p['readyEndpoints'],p['http'])),
 row('当前运行镜像',p['image'][0]),
 row('本轮 Kubernetes 变更 / 恢复 Commit','NOT_EXECUTED / NONE · 保持原状，不宣称完成恢复演练'),
 row('三节点 Ready',' · '.join(k+'='+val for k,val in p['nodes'].items())),
 '<details open><summary>1 · 打开原系统，核对期望状态与实际状态</summary>',
 *['<p><a href="'+E(url)+'">'+E(label)+'</a></p>' for label,url in links.items()],
 '<p>Argo 与 Grafana 可能要求登录。登录页可达不等于已验证登录后的面板或权限。此处没有同步、重启或发布按钮。</p></details>',
 '<details><summary>2 · 查看真实 Pod 状态与已有同步历史</summary>',
 *[row(q['name'],str(q['node'])+' · '+q['phase']+' · Ready '+str(all(c['ready'] for c in q['containers']))+' · Restarts '+str(sum(c['restartCount'] for c in q['containers']))) for q in p['pods']],
 *['<p>HISTORICAL · Argo history #'+E(h['id'])+' · '+E(h['deployedAt'])+' · <code>'+E(h['revision'])+'</code></p>' for h in p['argo']['history']],
 '<p>以上为已有真实部署历史，不是本轮新发布，也不证明执行过本轮恢复。当前 Warning Event 数量：'+str(len(p['warningEvents']))+'（仅 Kubernetes 现存记录，不代表历史从未出现故障）。</p></details>',
 '<details><summary>3 · 在已有授权管理终端执行只读排障命令</summary>',
 '<p>页面本身不执行这些命令，不接收凭据。请在已有 kubeconfig 的管理终端运行。</p>',
 '<pre><code>'+E('\n'.join([
 'kubectl get application petclinic -n argocd -o wide',
 "kubectl get application petclinic -n argocd -o jsonpath='{.status.sync.revision}{\"\\n\"}{.status.sync.status}{\" / \"}{.status.health.status}{\"\\n\"}'",
 'kubectl get deployment petclinic -n petclinic -o wide',
 'kubectl get pods -n petclinic -l app=petclinic -o wide',
 'kubectl get endpointslices -n petclinic -l kubernetes.io/service-name=petclinic',
 'kubectl get events -n petclinic --field-selector type=Warning --sort-by=.lastTimestamp',
 ]))+'</code></pre>',
 '<p>Grafana Explore 的 Loki 查询：<code>{namespace="petclinic"}</code>。先核对时间窗口，再查日志；不要仅凭 Pod Running 或 Argo Healthy 判断候选镜像已部署。</p></details>',
 '<p class="source-path">'+E(source.relative_to(ROOT))+' · SHA256 '+hashlib.sha256(source.read_bytes()).hexdigest()+'</p>',
 '<p>唯一演示阻塞：缺少已获准测试分支与非生产 Application 的 GitOps 绑定。本轮未新建 Application、修改目标分支或推送任何分支。生产发布 0 / Rollout 0。</p>',
 '</article>', '<!-- GITOPS_DEMO_RESULT_END -->']

page = ROOT / 'infra/security/manager-v2/view/index.html'
before = page.read_text()
assert '<!-- GITOPS_DEMO_RESULT_BEGIN -->' not in before
anchor = '<section id="pipeline-overview">\n'
assert before.count(anchor) == 1
after = before.replace(anchor, anchor + '\n'.join(lines)+'\n', 1)
page.write_text(after)
# Only this round's hunk, leaving previous unstaged work untouched.
with (OUT / 'page-only.patch').open('x') as f:
    f.write(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
        fromfile='a/infra/security/manager-v2/view/index.html',
        tofile='b/infra/security/manager-v2/view/index.html', n=1)))
print(json.dumps({'url':'http://security.devops.local:17862/#pipeline-overview',
    'gitopsRealChange':'INCOMPLETE','argoSync':p['argo']['sync'],'gitopsRevision':rev,
    'links':links,'sectionAdded':True,'productionMutations':0},ensure_ascii=False))
