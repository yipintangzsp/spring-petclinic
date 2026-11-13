> **2026-11-07 最终交付 / 功能冻结**：当前能力、操作与Backlog以[阶段交付说明](../../../../docs/DEVSECOPS-V2-HANDOFF-20261107.md)为准。下文保留开发阶段与特定入口的历史记录，不代表当前系统全部状态。

# Security Manager V2 — 本地结果页与受控操作预检

访问 <http://127.0.0.1:17862>，仅在启动服务的 Mac 上可访问。无需新依赖，使用现有 Node.js。

```sh
cd /Users/zhangsir/code/petclinic-platform-20261011
node infra/security/manager-v2/view/control.mjs start
node infra/security/manager-v2/view/control.mjs status
node infra/security/manager-v2/view/control.mjs stop
node infra/security/manager-v2/view/control.mjs restart
node infra/security/manager-v2/view/verify.mjs
```

默认展示最近三插件全部完成的 Service 项目记录，可切换最近身份拒绝、Java 正向、三插件负例、禁用、超时及不可用记录。来源为 `evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs/attempt2-*` 的固定允许列表，不执行新扫描。REAL 指历史受控真实工具执行；页面读取方式为 REPLAY。Cosign 仅受控离线 Blob 验签，不代表生产镜像信任验证。禁用与错误没有 Policy decision，不能视为 PASS。

展示前验证 summary/result/raw 的封存文件哈希、结果自身 digest 与 summary 绑定；数据不完整时显示 UNAVAILABLE。当前哈希匹配不等于恢复原有历史完整性，`ORIGINAL_EVIDENCE_INTEGRITY=FAILED` 保留。只输出允许字段，不展示 findings 内容、不提供任意文件下载。

Consumer 区独立读取先前 Loki、Dojo HTTP 协议测试的真实回执，明确为 MOCK + REPLAY，显示独立 Run ID 和来源。它们不属于当前所选插件 run，未向真实远端投递，也不拼为 same-run 16/16。

历史读取只接受本机 Host 与同源 GET/HEAD；新增固定 POST /api/run 接口，要求同源 Origin、随机会话 CSRF Token 和严格 JSON 白名单。无生产连接或生产凭据。服务仅绑定 127.0.0.1。PID、启动日志保存在本用户临时目录的专用 0700 子目录，停止时核对随机 instance 与 PID，拒绝全局 kill。停止后代码和证据保留，可再次启动；不会安装常驻启动项。

生产 Manager ACTIVE；Jenkins V2、Trivy、Dojo runtime 与 Summary V2 尚未闭环。Canonical Runtime 保持 14/16。Grafana 健康 GET 返回 200，但未认证用户/数据源 API 返回 401，因此未写入或覆盖现有 Dashboard。

回滚：运行上面的 stop 即停用本地入口。无需恢复生产配置，本页面不修改生产状态。不要删除或重写来源证据。


## 页面操作预检（本轮未完成真实扫描）

Live Validation Results 独立于 Historical Replay Results。选择三个插件之一及 Clean / Controlled Finding 后，按钮调用 `POST /api/run`。`GET /api/plugins` 返回当前身份、能力与本次服务随机 CSRF token，`GET /api/runs` 和 `GET /api/runs/:runId` 可刷新读取已保存记录。

**当前全部 BLOCKED**：原有三个 Real Runner 只支持经批准的 Linux 身份（非 root、NoNewPrivs、零 capabilities、固定受信工具和 fixture）。当前环境 Darwin，尚无已验证的 Mac 执行后端。本轮不更改上述契约、不安装工具、不伪装平台，也不远程回退到 devops。负载 > 核数的 75%、空闲内存 < 512 MiB、可用空间 < 512 MiB 时另行拒绝；这是本地小 fixture 的准入预算，不更改 Trivy guard。当前 Mac 资源采样不足，六项实际请求首先被资源预算拒绝。

新记录位于 `.devsecops/security-view-runs-v1/web-UUID/`，0700 目录、0400 文件、独立 UUID、O_EXCL 与 O_NOFOLLOW，不覆盖历史。最多 100 个记录目录，不自动删除历史。无任意命令、URL、路径、环境变量或参数入口；一次只允许一个请求，1 KiB 请求体、30 秒执行期限。当前没有启动任何扫描子进程，因此不将 timeout/descendant cleanup 或 Policy 单次求值声称为真实扫描验证通过。

条件允许时现有 Manager 的实际平台预检将生成 UNSUPPORTED / Policy=null / evaluationCount=0 的 Candidate，使用本地 dry-run Router；资源预算不满足时更早返回 BLOCKED，只有审计摘要，没有 Result Digest 或扫描报告。二者都不是 REAL。

运行 `node infra/security/manager-v2/view/actions-verify.mjs` 验证 HTTP 安全边界和六项 BLOCKED 持久化。浏览器自动化不可用，未声明实际点击按钮或完成 UI REAL 验收。用户可以在页面点击同一安全入口查看真实阻塞原因。停止/启动命令保持不变，历史证据只读展示保持可用。


## 本机域名入口

当前已验证 <http://security.devops.local:17862>，仅本机访问，属于带端口过渡入口。没有80端口代理。`/etc/hosts` 的本轮目标行是 `127.0.0.1 security.devops.local` 与 `::1 security.devops.local`；后者用于避免 macOS .local IPv6 查询等待。服务仍只监听127.0.0.1，IPv6首选客户端需要回退IPv4。Host/Origin按精确域名和端口允许，不使用通配。原localhost地址继续可用。

原始hosts备份：`/private/etc/hosts.security-v2-20261105-0724.before`；补IPv6前备份：`/private/etc/hosts.security-v2-dual-loopback-20261105.before`。回滚用 `sudoedit /etc/hosts` 仅删除上述两行，再 `sudo dscacheutil -flushcache` 与 `sudo killall -HUP mDNSResponder`；不得覆盖其他域名。启动/停止/重启仍使用上面的control.mjs命令。

Gitleaks Clean仍BLOCKED：当前预算与可信Darwin二进制/适配条件未满足，域名可用不代表真实扫描完成。详细事实见本轮 `evidence/2026-11-05/security-manager-v2-gitleaks-domain/REPORT.md`。


## Gitleaks Mac 预算测量修正

Gitleaks 改为 `mac-budget.mjs`：当前 Mac CPU ticks 差分得到忙碌比例；`vm_stat` 的 free+file-backed 页估算可回收内存；`statfs.bavail*bsize` 为可用磁盘；内核原生 memory-pressure enum 必须 NORMAL=0。不能把 dispatch 的 NORMAL bit=1 混入该 enum。内存与磁盘准入值仍各512MiB，CPU忙碌上限75%。load average只作诊断，不再代替CPU利用率。其他插件分支保持不变。

本轮真实域名请求仍因内核2/URGENT压力拒绝；没有执行工具或产生真实扫描Result。只获取官方固定版本公共资产清单，未安装/执行新工具。可信Mac工具与原生适配尚未完成，不能以修正预算代替扫描成功。详见 `evidence/2026-11-05/security-manager-v2-mac-admission/REPORT.md`。


## PetClinic Pipeline Overview（2026-11-05）

同一页面 <http://security.devops.local:17862#pipeline-overview> 增加七项真实来源概览：GitLab 提交、Jenkins #270、安全 Gate、候选构建 #2 与镜像、Argo CD、Kubernetes、Grafana/Loki。全部标为 HISTORICAL 并显示数据时点；本轮没有 LIVE 自动跨系统查询。页面刷新不采集生产数据，不持有生产凭证，无新增后端或服务重启。

历史记录证明候选构建与 #270 的构建证明校验；当前只读快照证明 GitOps revision、Synced/Healthy 和 PetClinic 3/3。候选镜像不同于运行镜像，不能将两段拼成同轮发布。当前 Job 固定审计提交，最近八次均为手动触发；GitLab Push Trigger 存在不等于自动触发验收通过。本轮未推送、未触发构建或部署。

全部导航经过实际 HTTP 检查；GitLab/Grafana 重定向登录，Jenkins 匿名返回403、已有授权身份读取归档返回200。Argo CD 应用深链404，因此使用已验证200的首页。Harbor页面200，但匿名artifact API401，镜像关联依据已归档构建证明，未冒充Registry实时读取。Prometheus三个PetClinic target UP，Loki最近五分钟有日志；不将日志原文放入页面。

定向验收及来源：evidence/2026-11-05/petclinic-pipeline-overview/acceptance.json、pipeline-snapshot.json。保留原有真实 Gitleaks PASS/FAIL 和 Jenkins #2/#3 链接。回滚仅移除 index.html 中 PETCLINIC_PIPELINE_OVERVIEW 标记之间的段落及新增导航链接，不影响生产或其他页面功能。
