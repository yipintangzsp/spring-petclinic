"""Minimal existing-page projection of one verified successful CI/CD build."""
from common import *
import html,hashlib,difflib,datetime
cd=json.loads((OUT/'result.json').read_text());proof=cd['gateReceipt'];v=json.loads((OUT/'verified.json').read_text());health=json.loads((OUT/'final-check.json').read_text());revocation=json.loads((OUT/'revocation.json').read_text())
assert cd['status']=='SUCCESS' and cd['updated']['verified'] and cd['restored']['verified'] and revocation['revoked']
E=lambda x:html.escape(str(x),quote=True)
def row(k,v):return '<div class="card-row"><span>'+E(k)+'</span><b>'+E(v)+'</b></div>'
project='http://gitlab.devops.local/root/petclinic-platform';build='http://jenkins.devops.local/job/security-gitlab-push-demo/'+str(cd['build'])+'/'
lines=['<!-- CI_CD_SAME_RUN_BEGIN -->','<article id="ci-cd-same-run" class="consumer" aria-labelledby="ci-cd-title">',
 '<div class="card-top"><h3 id="ci-cd-title">CI → CD · 同次真实安全门禁与 GitOps</h3><span class="tag real">VERIFIED · Jenkins #6 SUCCESS</span></div>',
 '<p>GitLab 测试分支 Push → Webhook #5 / Event #341 → Jenkins → 真实 Gitleaks → Policy PASS → 服务端验证并消费一次性回执 → 固定 GitOps 更新 → Argo 自动同步 → Kubernetes updated → Git Revert → baseline。</p>',
 '<p class="muted">HISTORICAL · 以下均来自同一 Build / Run 的真实执行归档，非实时查询。完成时间：<time>'+E(cd['completedAt'])+'</time>；构建耗时 '+str(v['duration'])+' ms。刷新页面不会重新执行。</p>',
 row('Trigger Commit',cd['triggerCommit']),
 '<p><a href="'+project+'/-/commit/'+cd['triggerCommit']+'">查看触发提交</a> · <a href="'+build+'">Jenkins #6 · SUCCESS</a> · <a href="'+build+'console">真实构建日志</a></p>',
 row('Gitleaks Run ID',cd['runId']),row('真实退出码 / Finding / Policy 求值次数','0 / 0 / 1'),
 row('Policy Decision','PASS · REAL_CONTROLLED_EXECUTION'),row('Result Digest',cd['resultDigest']),
 row('服务端 Gate 回执验证','VERIFIED · 固定 Clean 场景 / PASS / 未过期 / 单次消费 / 同 Run 与 Build 绑定'),
 row('Receipt ID',proof['receiptId']),row('Receipt Digest',proof['receiptDigest']),
 row('可信来源','UID 24021 扫描服务端生成 · 0440 只读回执 · UID 24022 无创建/修改权限'),
 '<div class="consumer-grid">']
for title,op,obs in [('GitOps Update → Kubernetes updated',cd['update'],cd['updated']),('GitOps Revert → Kubernetes baseline',cd['restore'],cd['restored'])]:
 lines+=['<div class="consumer"><h4>'+E(title)+'</h4>',
  '<p><a href="'+project+'/-/commit/'+op['afterCommit']+'"><code>'+E(op['afterCommit'])+'</code></a></p>',
  row('Argo Revision',obs['argoRevision']),row('Argo 状态',obs['sync']+' / '+obs['health']),row('实际 ConfigMap 值',obs['value']),
  row('resourceVersion',obs['resourceVersion']),'<p>实际采集：<time>'+E(obs['observedAt'])+'</time></p></div>']
lines+=['</div>',row('同一个 ConfigMap UID',cd['updated']['configMapUid']),
 '<p><a href="'+project+'/-/tree/security-demo/gitops-20261105">演示 GitOps 分支</a> · <a href="http://argocd.devops.local/">Argo CD：选择 petclinic-gitops-demo</a> · <a href="'+build+'artifact/evidence/jenkins-gitleaks-receipt.json">同次 Gate 归档</a> · <a href="'+build+'artifact/evidence/jenkins-gitops-receipt.json">同次 CD 归档</a></p>',
 '<details><summary>权限负例、通知来源和首次失败记录</summary>',
 '<p>实际拒绝：Finding FAIL、伪造 PASS、篡改摘要、过期回执、重复消费、任意 Git 命令、字段/引用注入、提权、PTY 和端口转发。项目 Token 对其他私有仓库的 receive-pack 授权请求为 401。</p>',
 '<p>main：固定入口拒绝任意 Git 命令；GitLab 身份仅 Developer 30，main 仍要求 Maintainer 40。未向 main 发起写入。凭据名称不等于 Job 级隔离；既有 built-in 的 Docker 权限未被用于执行或提权。</p>',
 '<p>Gate 后由 Jenkins 向现有 Argo 原生 webhook 发出固定分支通知，使用与 Application 一致的内部仓库 web_url。此通知不冒充 GitLab 投递证据；原始触发由 GitLab Event #341 与 Jenkins GitLabWebHookCause 证明。</p>',
 '<p><a href="http://jenkins.devops.local/job/security-gitlab-push-demo/5/">首次尝试 #5 · FAILURE</a>：等待窗口未覆盖 Argo 缓存检测，已生成 Revert 并恢复。修复原生通知后 #6 完成完整闭环。#5 不计为本次成功证据，也未与 #6 拼接。</p>',
 '<p>补验推送前一次旧 bundle 路径校验被拦截，未发生 Push；修正路径后才推送固定提交。所有旧记录保留。</p>',
 '<p>授权撤销已实际验证：本次临时 GitLab Token 已撤销，随后 receive-pack 返回 '+str(revocation['revokedTokenReceivePackHttp'])+'；服务端 Token 文件已删除。此一次性演示已结束，后续写入需新的显式短期授权，不会自动重复执行。</p>',
 '</details>',
 '<p>生产核对时间：'+E(health['host']['observedAt'])+'。PetClinic 3/3、HTTP 200、三节点 Ready、Argo Synced/Healthy；生产 Deployment、GitOps main、Jenkins #270、V1 Summary、Docker Socket 0660 均保持原状。生产 Security Manager NOT_ACTIVE；Canonical Runtime 14/16；Release=0 / Rollout=0。</p>']
for name in ['verified.json','result.json','final-check.json','negative-replay.json','revocation.json']:
 f=OUT/name;lines.append('<p class="source-path">'+E(f.relative_to(ROOT))+' · SHA256 '+hashlib.sha256(f.read_bytes()).hexdigest()+'</p>')
lines+=['</article>','<!-- CI_CD_SAME_RUN_END -->']
page=ROOT/'infra/security/manager-v2/view/index.html';before=page.read_text();assert '<!-- CI_CD_SAME_RUN_BEGIN -->' not in before
anchor='<section id="pipeline-overview">\n';assert before.count(anchor)==1
after=before.replace(anchor,anchor+'\n'.join(lines)+'\n',1);page.write_text(after)
with (OUT/'page-only.patch').open('x') as f:f.write(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/infra/security/manager-v2/view/index.html',tofile='b/infra/security/manager-v2/view/index.html',n=1)))
print('Rendered one verified same-build CI/CD chain into existing page')
