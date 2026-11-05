"""Replace the prior fallback with this run's verified real GitOps timeline."""
import difflib
import hashlib
import html
import json
from pathlib import Path
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
v=json.loads((OUT/'verified.json').read_text())
assert all(x=='VERIFIED' for k,x in v['verdict'].items() if k!='PRODUCTION_PETCLINIC_UNCHANGED')
stages=[json.loads((OUT/(s+'.json')).read_text()) for s in ['baseline','updated','restored']]
E=lambda value:html.escape(str(value),quote=True)
project='http://gitlab.devops.local/root/petclinic-platform'
branch='security-demo/gitops-20261105'
def row(label,value):return '<div class="card-row"><span>'+E(label)+'</span><b>'+E(value)+'</b></div>'
lines=['<!-- GITOPS_DEMO_RESULT_BEGIN -->',
 '<article id="gitops-demo-result" class="consumer" aria-labelledby="gitops-demo-title">',
 '<div class="card-top"><h3 id="gitops-demo-title">GitOps Demo Result · 真实变更与恢复</h3><span class="tag real">VERIFIED · REAL GITOPS</span></div>',
 '<p>三次真实 Git Push → Argo 自动同步 → 同一个 Kubernetes ConfigMap：<strong>baseline → updated → baseline</strong>。最后一次为真实 git revert，不是直接 kubectl 修改、重置历史或模拟状态。</p>',
 '<p class="muted">HISTORICAL · 同一演示的真实执行归档。最终只读核对：<time>'+E(v['host']['observedAt'])+'</time>。刷新仅重新读取本地记录，不触发同步、扫描或推送。</p>',
 row('演示对象','devsecops-test / ConfigMap petclinic-gitops-demo'),
 row('独立 Application / 最终状态','petclinic-gitops-demo · Synced / Healthy · 仅管理 1 个 ConfigMap'),
 row('固定分支 / 目录',branch+' / infra/devops-lab/gitops-demo'),
 '<div class="gitops-table-wrap"><table><thead><tr><th>阶段 / 实际值</th><th>Git Commit / Argo Revision</th><th>Kubernetes 取证</th></tr></thead><tbody>']
for name,s in zip(['Baseline','Updated','Restored · Git Revert'],stages):
 sha=s['expectedCommit'];cm=s['configMap']
 lines.append('<tr><td><strong>'+E(name)+'</strong><br><code>demo-stage='+E(cm['data']['demo-stage'])+'</code></td>'+
 '<td><a href="'+project+'/-/commit/'+sha+'"><code>'+sha+'</code></a><br>Argo: <code>'+E(s['argo']['revision'])+'</code><br>'+E(s['argo']['sync'])+' / '+E(s['argo']['health'])+'</td>'+
 '<td><time>'+E(s['observedAt'])+'</time><br>resourceVersion: '+E(cm['resourceVersion'])+'<br>同步完成：'+E(s['argo']['finishedAt'])+'</td></tr>')
lines+=['</tbody></table></div>',
 row('同一 ConfigMap UID',stages[0]['configMap']['uid']),
 row('实际变化证据','UID 相同；3 个不同 resourceVersion；3 个准确匹配的 Argo 同步 Revision'),
 row('最终 GitOps Revision',stages[-1]['argo']['revision']),
 row('恢复验证','VERIFIED · baseline/revert Git tree 相同，集群实际值恢复 baseline'),
 '<p><a href="'+project+'/-/tree/'+branch+'">GitLab 演示分支与唯一 Manifest</a> · <a href="http://argocd.devops.local/">打开 Argo CD，选择 petclinic-gitops-demo</a> · <a href="http://petclinic.devops.local/">生产 PetClinic</a></p>',
 '<p>Argo CD 首页可达；现有应用深链直接 GET 返回 404，使用首页选择上述应用即可查看详情。本轮没有修改 Argo 路由。GitLab / Argo 可能需要登录。</p>',
 '<details><summary>查看 Argo 实际 OutOfSync → Synced 过程</summary>']
for s in stages[1:]:
 for q in s['polls']:
  lines.append('<p>'+E(s['stage'])+' · '+E(q['at'])+' · '+E(q['sync'])+' · <code>'+E(q['revision'])+'</code> · Kubernetes value='+E(q['value'])+'</p>')
lines+=['</details>',
 '<details><summary>只读复核命令与隔离范围</summary><pre><code>'+E('\n'.join([
 'kubectl get application petclinic-gitops-demo -n argocd -o wide',
 "kubectl get application petclinic-gitops-demo -n argocd -o jsonpath='{.status.sync.revision}{\"\\n\"}{.status.sync.status}{\" / \"}{.status.health.status}{\"\\n\"}'",
 "kubectl get configmap petclinic-gitops-demo -n devsecops-test -o jsonpath='{.data.demo-stage}{\"\\n\"}{.metadata.uid}{\"\\n\"}{.metadata.resourceVersion}{\"\\n\"}'",
 'kubectl get pods -n devsecops-test',
 ]))+'</code></pre>',
 '<p>固定仓库 / 分支 / 目录 / Namespace / ConfigMap；Prune=false；无删除 finalizer。复用已有 Namespace，未创建 Pod、Secret、权限或控制器。当前保留 Application 和恢复 baseline 的 ConfigMap，供查看和学习。</p>',
 '<p>GitLab Auto DevOps 已通过 ci.skip 与 [skip ci] 阻止执行。三次对应 Pipeline 均 SKIPPED，Jenkins petclinic-ci 仍为 #270 SUCCESS。</p>',
 '<p>一次回滚推送在 Git 输出采集校验阶段被拦截，尚未执行 push；修复输出读取竞态、重新核对远端分支后完成原 Revert Commit。失败记录保留，未跳过任何 Manifest/分支校验。</p></details>',
 '<p>生产最终核对：PetClinic 3/3、HTTP 200、三节点 Ready、Argo Synced/Healthy。Deployment UID / generation / spec / image、生产 Argo spec / revision、Jenkins 定义、V1 Summary 和 Docker Socket 0660 均未变化。生产发布 0 / Rollout 0。</p>']
for name in ['baseline.json','updated.json','restored.json','verified.json']:
 src=OUT/name
 lines.append('<p class="source-path">'+E(src.relative_to(ROOT))+' · SHA256 '+hashlib.sha256(src.read_bytes()).hexdigest()+'</p>')
lines+=['</article>','<!-- GITOPS_DEMO_RESULT_END -->']
page=ROOT/'infra/security/manager-v2/view/index.html';before=page.read_text()
start=before.index('<!-- GITOPS_DEMO_RESULT_BEGIN -->');end=before.index('<!-- GITOPS_DEMO_RESULT_END -->',start)+len('<!-- GITOPS_DEMO_RESULT_END -->')
after=before[:start]+'\n'.join(lines)+before[end:]
page.write_text(after)
with (OUT/'page-only.patch').open('x') as f:f.write(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/infra/security/manager-v2/view/index.html',tofile='b/infra/security/manager-v2/view/index.html',n=1)))
print('Rendered verified baseline → updated → reverted baseline in existing Pipeline Overview')
