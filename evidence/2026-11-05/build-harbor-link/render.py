"""Add one evidence-bound card to the existing Overview. No new service/API."""
import json,html,hashlib
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
p=json.loads((OUT/'verified.json').read_text());E=lambda s:html.escape(str(s),quote=True)
src='evidence/2026-11-05/build-harbor-link/verified.json'
rows=[('源码 Commit · HISTORICAL',p['commit']),
 ('镜像构建 · HISTORICAL','petclinic-candidate-build #2 · SUCCESS'),
 ('安全验收 · HISTORICAL','petclinic-ci #270 · SUCCESS · Security Gate PASS (enforce)'),
 ('Gate 原始依据 · HISTORICAL','Security Gate 已完成、无错误；V1 Summary source / auditTargetImage 精确绑定；Gitleaks success / 0 Findings'),
 ('Harbor Repository · LIVE 查询快照',p['harbor']['repository']),
 ('Image Tag · LIVE 查询快照',p['harbor']['tag']),
 ('Image Digest · LIVE 查询快照',p['harbor']['digest']),
 ('Harbor 实际查询时间（UTC）',p['observedAt']),
 ('镜像实际构建时间（UTC）',p['imageBuild']['startedAt']+' → '+p['imageBuild']['completedAt']),
 ('#270 安全归档时间（UTC）',p['securityBuild']['summaryRecordedAt']),
 ('关联校验','VERIFIED · 已验证公开签名的构建与安全验收证明；BuildKit Digest = #270 auditTargetImage = Harbor Digest'),
 ('新构建 / 发布 / Rollout','无需新构建 / 0 / 0')]
card='''<!-- BUILD_HARBOR_LINK_BEGIN -->
<article id="build-harbor-link" class="consumer">
<div class="card-top"><h3>安全构建 → Harbor 镜像 · 真实可追溯关联</h3><span class="tag real">VERIFIED · HISTORICAL + LIVE QUERY SNAPSHOT</span></div>
<p>同一源码 Commit → 候选镜像构建 #2 → 指定 Digest → 安全验收 #270（enforce Gate 通过）→ Harbor 现存镜像。构建与安全验收是两个明确独立的历史 Job，归档证明将它们绑定到同一个镜像。</p>
'''
for k,v in rows:card+='<div class="card-row"><span>'+E(k)+'</span><b>'+E(v)+'</b></div>\n'
links=[('http://gitlab.devops.local/root/petclinic-platform/-/commit/'+p['commit'],'GitLab 对应提交'),
 (p['imageBuild']['url'],'镜像实际构建 #2'),(p['securityBuild']['url'],'安全验收 #270'),
 (p['securityBuild']['url']+'artifact/.devsecops/security-summary.json','原始 Security Summary'),
 (p['securityBuild']['url']+'artifact/.devsecops/build-attestation-verification.json','归档构建绑定验证'),
 (p['harbor']['apiUrl'],'Harbor 精确 Digest 记录（需登录）'),(p['harbor']['uiUrl'],'Harbor 仓库')]
card+='<p>'+' · '.join('<a href="'+E(u)+'">'+E(t)+'</a>' for u,t in links)+'</p>\n'
card+='''<p>HISTORICAL 为 Jenkins 原始归档；LIVE 查询快照为本轮已授权 Harbor GET 的 HTTP 200 结果，刷新页面不会重查。Tag 仅展示实际查询值，Commit 绑定来自归档 BuildKit 元数据与已验签证明，不依赖 Tag 名称推断。</p>
<p>此候选镜像不同于当前部署的运行镜像；与上方/下方 security-gitlab-push-demo #4 无构建关联。未证明候选镜像晋升或本轮生产发布，也不表示 V2 Runtime 已达到 16/16。</p>
<p class="source-path">'''+src+' · SHA256 '+hashlib.sha256((OUT/'verified.json').read_bytes()).hexdigest()+'''</p>
</article>
<!-- BUILD_HARBOR_LINK_END -->
'''
f=ROOT/'infra/security/manager-v2/view/index.html';text=f.read_text()
assert '<!-- BUILD_HARBOR_LINK_BEGIN -->' not in text
text=text.replace('<!-- GITLAB_GITLEAKS_AUTOCLOSE_BEGIN -->',card+'<!-- GITLAB_GITLEAKS_AUTOCLOSE_BEGIN -->',1)
text=text.replace('候选镜像与运行镜像不同。当前 Harbor artifact 匿名 API 返回 401；不能声称已实时核验 Registry 内容。','候选镜像与运行镜像不同。此旧快照当时匿名 API 返回 401；本轮已授权查询的 HTTP 200、Tag 与 Digest 关联见上方“安全构建 → Harbor 镜像”。')
f.write_text(text)
print('Existing Overview card added; historical evidence files unchanged.')
