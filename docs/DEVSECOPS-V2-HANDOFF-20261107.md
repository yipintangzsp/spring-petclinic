# DevSecOps V2 阶段交付与功能冻结

**状态：DEMO READY；功能冻结。** 验收基线 `a56598e0`，2026-11-07 北京时间约 20:58 完成只读交付检查。本说明是本期当前交付入口；早期 README 中“全部 BLOCKED / offline-only / Consumer MOCK”等描述属于当时阶段，保留为历史，不代表现在的全部能力。冻结不停止现有页面，也不自动触发扫描或下一期建设。

## 入口与已验证能力

仅从运行页面的 **Mac** 访问；服务绑定 `127.0.0.1:17862`，未开放 LAN、未新增80端口代理。

- [管理与插件总览](http://security.devops.local:17862/#candidate-overview)
- [真实执行与历史结果](http://security.devops.local:17862/#live-validation)
- [Pipeline Overview](http://security.devops.local:17862/#pipeline-overview)
- [Grafana V2](http://grafana.devops.local/d/security-manager-v2-candidate/devsecops-security-manager-v2-overview)；查看下述 Run 时设置 project=`python-fixture`、Run/Digest，并选择其执行时间段（2026-11-07 16:35–16:41 北京时间）。原系统可能要求合法登录。

| 能力 | 本期交付与边界 | 主要证据 |
|---|---|---|
| 管理页面与配置 | 13 插件 Registry；全局/插件开关、low/standard/strict、项目覆盖与持久化；Host/Origin/CSRF、loopback、固定输入白名单 | `infra/security/manager-v2/`；本轮 `page-check.json` |
| Gitleaks / Semgrep | 受限 Linux 真实 Clean PASS / Finding FAIL；真实源码 Commit 扫描已闭环 | 本轮 `historical-plugin-records.json`；`evidence/2026-11-07/timeout60/` |
| Cosign | 3.1.4 固定非生产 Blob Valid PASS / Invalid FAIL，真实验签；不是候选 Harbor 镜像签名证明 | `evidence/2026-11-06/cosign-web-real/acceptance.json` |
| SBOM | 共用 Registry/Runner/Adapter/Policy/Router，Java A/B 独立输入、配置、结果授权；各一次真实 CycloneDX JSON1.6、11组件；原始文件可读 | `evidence/2026-11-06/sbom-second-project/acceptance.json`；`infra/security/manager-v2/sbom/README.md` |
| Policy / Artifact / Router | Policy 单次求值；原生报告、Fact、Result Digest、Candidate Summary/Seal 绑定；Router复用同一结果，不自行判 PASS | `evidence/2026-11-07/timeout60/acceptance.json` |
| Loki / Grafana | 新扫描自动投递、Loki按Run/Digest回查；V2独立看板8面板，验收时5个有数据、2个No data、1个静态说明 | `evidence/2026-11-07/timeout60/grafana-query.json`；本轮 `grafana-check.json` |
| DefectDojo | 原 Semgrep 真实两条风险写入独立 DEMO Product7 / Engagement4，Finding [6628](http://defectdojo.devops.local/finding/6628)、[6629](http://defectdojo.devops.local/finding/6629)；已查询回验。同 journal 重投零HTTP，不声称分布式exactly-once | `evidence/2026-11-06/dojo-real-execution/README.md`、`verdict.json` |
| CI/CD | Jenkins [Clean #2](http://jenkins.devops.local/job/security-gitleaks-demo/2/) SUCCESS / [Finding #3](http://jenkins.devops.local/job/security-gitleaks-demo/3/) FAILURE及后续跳过；#6非生产Gate回执→GitOps→Argo→ConfigMap updated→baseline；#12真实Commit→共享Manager→Gitleaks→Policy→Loki/Grafana | `evidence/2026-11-06/ci-cd-real/attempt2/result.json`；`evidence/2026-11-07/timeout60/verdict.json` |
| 供应链与部署追溯 | Harbor候选、构建/Commit、GitOps/Argo/Pod实际Digest及差异真实展示，不拼接为同轮发布 | Supply Chain Security / Pipeline Overview；`evidence/2026-11-06/supply-chain-view/` |
| 跨项目/流水线 | SBOM A/B共用实现；非生产Jenkins通过标准项目/仓库/Commit/CI身份契约调用共享Manager。请求不接受任意路径、命令或Scanner参数 | `infra/security/manager-v2/ci/`、`sbom/` |

项目隔离是本机 Operator 与项目级 API capability/结果授权，SBOM A/B 共用受限 Linux UID；不是多租户 OS 隔离或企业 SSO。真实记录按原始时间标为历史；REPLAY、MOCK、CANDIDATE、NOT_ACTIVE、BLOCKED/UNAVAILABLE 不升级成生产或实时结果。旧 #9/#10/#11 失败和 UNKNOWN 状态全部保留。

## 最终真实 Commit 样例

- 项目 `python-fixture`，GitLab 项目12 `root/petclinic-platform` 的获授权非生产分支；它是逻辑项目映射，不冒称独立 GitLab 仓库。
- Commit `a69104ba1bf88b74cc57a420888ee692b88c8c48` → Webhook347 → [Jenkins #12 SUCCESS](http://jenkins.devops.local/job/security-gitlab-push-demo/12/)。这是原Push事件重投，没有新生产Push。
- Run `web-a3378992-4eb3-414d-ac5d-bf46ba3034cf`，REAL / COMPLETED；完整输入830文件、46,162,841字节，含整个6,221,319字节的 `controller.json`。
- Source Snapshot SHA256 `943967bd6eab180d71f9b1c8e197fdad9c89148b0fec4c69f5a6d2d32d124c03`。
- Gitleaks PID2465700，13.665秒，退出码1；95条原生命中均匹配既有路径/规则/行哈希审核项，阻断0，Policy PASS，求值1次。不是“发现数为0”，本期未改变审核表或Policy。
- Result Digest `64e7678195b71aa7fb689a0149ddc6896b9d1af51e3ca48d00dad4c44b511bd5`；Loki及Grafana已查回同一值。
- Fixture 默认10秒不变；项目级真实源码扫描60秒上限绑定批准Commit，`controller.json` 的8MiB例外不成为全局默认；全局单文件仍4MiB，其余输入/CPU/内存/磁盘/并发保护保留。

## 保留的完整架构与未来 Backlog

保留统一主干：项目配置/授权 → Plugin Registry与能力/开关检查 → 独立插件执行 → 原生报告/Normalize → Policy单次求值 → Artifact/Summary → Result Router → 本地/Loki/DefectDojo等出口 → 管理页面/Grafana。插件实现、项目配置、CI适配分离，继续要求可插拔、可管理、可开关、总链路、真实展示、跨项目与跨DevOps流水线可移植。

13项定义全部保留：`gitleaks`、`semgrep`、`cosign`、`sbom`、`trivy`、`sonarqube`、`sops`、`kyverno`、`falco`、`kubescape`、`zap`、`provenance`、`build-provenance`。定义/父Gate兼容性/Candidate不等于已有真实 Web Runner或生产启用。

以下仅转入未来Backlog，本期不实施、不删功能：

1. Harbor旧候选 `sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55` 的SBOM可信Digest绑定仍 **UNVERIFIED**；历史Maven SBOM和A/B Fixture SBOM均不能替代该证明。
2. 该候选 Cosign **SIGNATURE_MISSING**，发布批准 **NOT_APPROVED**，候选部署 **NOT_DEPLOYED**；#270历史验收/audit-only不等于现行enforce发布批准。不得借受控Blob PASS或#12演示PASS晋升镜像。
3. Trivy真实Runtime、未激活插件的实时入口/治理、Summary V2迁移、不可变产物Runtime与生产Manager激活仍未完成。Canonical Runtime保持 **14/16**，不拼接不同运行形成16/16。
4. GitLab CI、GitHub Actions及其他CI平台、Python/Go SBOM适配未验证；现有标准契约保留，不能声称任意项目可即插即用。
5. `ORIGINAL_EVIDENCE_INTEGRITY=FAILED` 永久保留；现存文件哈希可读不等于恢复原始历史完整性。非生产Dojo闭环不提升旧Canonical Dojo/Trivy Runtime结论。

## 日常使用与最小回滚

在 Mac 仓库根目录：

```sh
cd /Users/zhangsir/code/petclinic-platform-20261011
node infra/security/manager-v2/view/control.mjs status
node infra/security/manager-v2/view/control.mjs start
node infra/security/manager-v2/view/control.mjs open
# 停止或再次启动（只影响本地页面）
node infra/security/manager-v2/view/control.mjs stop
node infra/security/manager-v2/view/control.mjs start
# 需要加载已批准变更时才 restart
node infra/security/manager-v2/view/control.mjs restart
```

`open` 使用受保护的本机 Operator 凭据生成一次性登录票据，不输出Token；浏览器会话过期时重新运行。日常演示优先只读查看本页入口、#12及历史PASS/FAIL、两项目SBOM、Dojo链接和Grafana指定Run；**冻结验收不点击生成/扫描、不重投Webhook、不运行回归脚本**。普通控件只影响非生产Candidate，不影响生产Gate。

新受控Fixture执行仍受开关、授权与资源准入限制，不能承诺每次资源可用。真实Commit CI通道为单次授权通道，**已关闭**：短期Git Token撤销，原非生产Job/SSH入口恢复；后续若需再次执行，须明确授权按原边界重建，而非把历史#12当成持续运行的CI服务。

凭据引用仅在受保护存储：本机 `.devsecops/` Operator/项目凭据、原 `.ssh/` key、macOS Login Keychain；禁止复制至Git、文档、日志或页面。Grafana原Service Account的同权限Token于2026-11-07 16:40北京时间换发，有效24小时，存原Keychain service `petclinic-security-manager-v2-grafana` / account `security-manager-v2-dashboard`；不是本轮遗留CI Token。到期后通过合法管理入口按相同权限续期，未配置自动续期；Dojo演示Token已撤销，人工查看需合法Dojo登录。

最小回滚优先 `control.mjs stop`，保留所有代码、配置、`.devsecops/security-view-runs-v1`及封存证据。需要暂停某非生产插件时使用现有开关，不删除历史；恢复演示默认配置前先核实当前配置及无运行任务。文档回滚仅定向撤回本次文档提交。执行代码回滚需另行批准、先停止页面并保护工作区，只撤回明确目标提交；禁止 `git reset --hard`、清理整个工作区、覆盖历史或操作生产部署。**本期没有需要回滚的生产发布。**

## 冻结验收与范围

本期最终只读检查：页面HTTP200；三插件精确历史PASS/FAIL、#12和SBOM A/B可读；异项目读取被拒绝；Grafana非管理员查询匹配#12 Run/Digest。生产PetClinic3/3、业务HTTP200、三节点Ready、ArgoSynced/Healthy；生产Spec、镜像、Jenkins#270SUCCESS与V1 Summary未变，Docker0660。实际检查时间和结果位于 `evidence/2026-11-07/v2-final-freeze/`。

CI临时Token/Askpass、UNIX Socket/capability、源码和scan临时目录已清理；只保留非敏感结果与诊断。现有页面、受控工具/缓存、长期受保护凭据引用及历史Artifact属于交付资产，不当成临时垃圾删除。

工作区原有5份运维文档和 `view/index.html` 的未提交修改保持原状，不纳入本次文档提交；早期其他未跟踪成果也不清理。本次不新增功能、不扫描、不构建、不修改生产配置、不Push、不Release、不Rollout。冻结是停止本期改造，不是将全部13插件启用或激活生产Manager。此后只接受明确的新任务，不自动启动Backlog。

```text
DEVSECOPS_V2_DEMO = READY
REAL_COMMIT_SCAN = VERIFIED
PRODUCTION_SECURITY_MANAGER = NOT_ACTIVE
FINAL_WIRED_CAPABILITY = 14/16
ORIGINAL_EVIDENCE_INTEGRITY = FAILED
PRODUCTION_RELEASE = NO
PRODUCTION_ROLLOUT = NO
```
