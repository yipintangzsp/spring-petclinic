# 复现说明 — 供应链第二步：Cosign 签名 / Provenance 链 / Kyverno 准入 / 发布决定（2026-11-12）

对象：Harbor `petclinic/petclinic` 候选 OCI Index `sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55`
（amd64 子 Manifest `sha256:2bd9c1c4…`、arm64 子 Manifest `sha256:06a51570…`）。
锚点：`binding-anchor.json`（本步封存包 sealDigest 与记录 digest 带外固定；同时交叉引用第一步锚点）。
前置：第一步证据 `evidence/2026-11-12/supply-chain-step1-sbom-binding/`（本目录验证脚本会读它的 `binding-anchor.json` 做交叉链接）。

## 0. 前置
- Mac 仓库 `~/code/petclinic-platform-20261011`，分支 `fix/security-manager-plugin-switches`，HEAD `b36b7554`；Node 用 `/opt/homebrew/bin/node`。
- 生产 Manager 保持 NOT_ACTIVE；未触发 Jenkins；未做 Argo/GitOps 变更；候选未部署（运行中 Index 仍为 `sha256:489cb821…`，本轮末复查一致）。
- 凭据红线：Harbor 只读拉取用项目 robot（值不入文件）；签名私钥只在 devops root 的 700 临时目录内解密使用、用后销毁，未写入任何证据/日志；未借用 Jenkins 生产 `harbor-creds`；未使用盘点中发现的宿主机 docker-config 管理员身份；未新建任何账号。

## 1. 盘点（结论见小结）
- 既有签名路径：`infra/security/promotion/sign-approve.mjs` 与 `infra/security/signing.mjs`——SOPS 加密包 `infra/security/secrets/signing-bundle.enc.json` + age 密钥（Jenkins 凭据 `platform-signing-age`；devops 上另有 bootstrap 副本 `/opt/platform-security/bootstrap-20261027/signing.agekey`，root 600）。
- cosign-real（V2）为 verify-only、固定 Blob、且明确禁止生产信任钥用于受控对象——不能签候选，属预期，本轮未用它冒充。
- Kyverno：集群现行 `ClusterPolicy/devsecops-signed-images`（Enforce、Ready）即仓库 `infra/security/integration-resources.json` 中的策略，覆盖 `petclinic` 与 `devsecops-supply-chain` 命名空间，公钥即 `infra/security/cosign.pub`；拉取密钥 `kyverno-registry-pull` 在 `devsecops-system`。
- 发布批准既有格式：`promotion/contract.mjs` 的 `approvedRelease()` 对象 + `sign-approve.mjs` 对批准 JSON 做 sign-blob/verify-blob。

## 2. 候选字节获取与 Harbor 签名附属物核查（devops，root 只读）
脚本 `raw/scripts/fetch.sh`，日志 `raw/fetch.log`：
- 以 robot 只读凭据 GET Index 与两子 Manifest 原始字节，sha256 逐一断言等于钉死 digest（全过）。
- 三个 legacy `.sig` 标签 HEAD 均为 **404**（与 2026-11-05 预检一致）；referrers 接口 200（内容为第一步已记录的两份 buildx attestation）。
- 工具身份：devops `/usr/local/bin/cosign` v3.1.4，sha256 `ade83b7a…` 与平台 `scanner-tools.json` 钉死值一致。

## 3. Cosign 真实签名（devops，root 受控运行）
脚本 `raw/scripts/sign.sh`，日志 `raw/sign.log`、`raw/*.sign.log`：
- `sops decrypt` bootstrap 副本签名包（age 密钥为既有 signing 密钥）到 700 临时目录；先导出公钥并断言与 `cosign.pub` **逐字一致**，再 `cosign sign-blob --new-bundle-format=false --use-signing-config=false --tlog-upload=false`（与 `sign-approve.mjs` 同旗标）对 Index/两子 Manifest 的**确切字节**签名；结束 trap 删除临时目录（事后 `ls /tmp/sc2-sign.*` 不存在复核）。
- 签名 sha256：index `db63ccf7…`、amd64 `4c8e9584…`、arm64 `033bf03f…`（各 96 字节 base64）。
- 验签（`raw/scripts/verify.sh`、`raw/verify.log`）：`cosign verify-blob --key cosign.pub --insecure-ignore-tlog=true` 正例 3/3 rc=0；负例 N1 篡改清单、N2 Index 签名配子清单、N3 双架构互换、N4 篡改签名、N5 缺签名，全部 rc=1 被拒。
- **范围声明**：签名落在证据层（离线 blob 签名），**未**写入 Harbor（无合规写身份，见小结缺口）——Kyverno 无法消费这份签名，候选在集群侧仍是未签名状态。
- 事故记录：文档签名第一轮因 Mac `base64` 需 `-i` 参数、传输得到空文件，签了空内容——该轮签名已全部作废丢弃，以文件 sha256 对账（`ec3d632e…`/`1e826d60…`）后重签并验签 rc=0（`raw/signdocs.log` 为重签轮日志）。

## 4. Provenance 证明链与发布决定（Mac 生成 → devops 签名 → Mac 封存）
- `artifact/provenance-chain.json`：关联 DSSE 构建来源（commit `9a78cc89…`、candidate-build #2、petclinic-ci #270、Summary sha `ec9ee51a…`）+ 第一步 SBOM 绑定封存锚 + 本轮签名与验签结果 + Kyverno 用例 + Trivy V2 门禁事实（FAIL，HIGH 2）。
- `artifact/release-decision.json`：与 Index digest 绑定的发布决定记录，`status=NOT_APPROVED`（理由见记录内 blockers：Harbor 签名附属物缺失、Trivy V2 FAIL、单构建门禁证据集不齐）；记录明示不等于部署、生产切换需另行审批。
- 两份文档均按平台既有模式 sign-blob + verify-blob（脚本 `raw/scripts/signdocs.sh`，日志 `raw/signdocs.log`，签名记录在 `artifact/signature-*.json`）。

## 5. Kyverno 签名准入正反例（隔离命名空间，真实执行）
脚本 `raw/scripts/kyverno.sh`，原始输出 `raw/kyverno*.log`、`raw/dryrun-*`、`raw/real-*`；策略为集群现行策略、未新建未修改：
- 正例：已签名 fixture（build 270，`sha256:86ddc3e1…`）`kubectl create --dry-run=server` rc=0 放行；并真实创建 Pod rc=0，随即删除。
- 负例：未签名 fixture（`sha256:d65f8d7f…`）rc=1、`wrong-key` fixture（`sha256:4a4c9aab…`）rc=1，均被 `devsecops-signed-images` 拒绝。
- 候选本身：rc=1 被拒，原文 `no signatures found`——与离线签名的范围声明一致。
- 清理：测试 Pod 已删，`devsecops-supply-chain` 命名空间复查为空。

## 6. 封存与独立验证
```sh
cd evidence/2026-11-12/supply-chain-step2
node build-step2-artifact.mjs   # 重建前先删 artifact/ 与 binding-anchor.json（artifactStore 拒绝已存在目录）
node verify-step2.mjs           # 期望 18 项全 PASS、exit 0（实测 raw/verification-output.log）
```
验证含：seal 校验、记录 digest、决定→证明链 sha 链接、五份签名用纯 Node ECDSA 离线复验（不依赖 cosign 二进制）、原始字节 digest 断言、第一步锚点交叉链接；负例：篡改 Index 字节、架构互换、文档篡改、seal 篡改，全部被拒。

## 7. 回归（纯净克隆，基线口径，同第一步）
```sh
git clone ~/code/petclinic-platform-20261011 /tmp/sc2clone && cd /tmp/sc2clone
git checkout fix/security-manager-plugin-switches   # HEAD b36b7554
node --test infra/security/manager-v2/config.test.mjs infra/security/manager-v2/registry.test.mjs infra/security/manager-v2/core.test.mjs infra/security/manager-v2/runner.test.mjs infra/security/manager-v2/integration.test.mjs infra/security/manager-v2/trivy-real.test.mjs infra/security/manager-v2/view/origins.test.mjs infra/security/manager-v2/view/mac-budget.test.mjs infra/security/manager-v2/view/loki-delivery.test.mjs infra/security/manager-v2/observability/queries.test.mjs   # 期望 89/89
node --test infra/security/*.test.mjs infra/observability/*.test.mjs   # 期望 147/147
```
实测日志 `raw/suite1.log`、`raw/suite2.log`。本轮零源码改动（仅新增证据目录），回归为基线复测性质。
