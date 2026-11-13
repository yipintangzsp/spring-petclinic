# 复现说明 — 供应链 B4 第二步：Cosign 签名 / Provenance 链 / Kyverno 准入 / 发布决定（2026-11-13）

对象：Harbor `petclinic/petclinic` 候选 OCI Index `sha256:a8e800ef6a66081eebbd2a620f24f42c16b36dc33860bdf83d934e63a9ffb072`
（amd64 子 Manifest `sha256:5bed9d1ddeae0a136577d55e72cf6cfe9f57d55d0390cdc15c8a98bc50c02169`、arm64 子 Manifest `sha256:3cc885b3cbe2709ef7aaf384382477a33d996cfd4125d4489e7d3446793c6e57`；tag `0.10.0-ci-1000007`，构建 `petclinic-candidate-build` #7、修复提交 `318d479fb458ff229d0e10ed99ae7317f7427625`）。
锚点：`binding-anchor.json`（本步封存包 sealDigest 与记录 digest 带外固定，并交叉引用第一步——本轮 SBOM 绑定包 `evidence/2026-11-13/supply-chain-b4-1000007/binding-anchor.json`）。
前置：本轮 SBOM 绑定与双架构复扫已在 `supply-chain-b4-1000007` 封存（验证 29/29）。
本轮按先例**不提交**：本目录全部文件为未跟踪新增。

## 0. 前置
- Mac 仓库 `~/code/petclinic-platform-20261011`，分支 `fix/security-manager-plugin-switches`；Node 用 `/opt/homebrew/bin/node`。
- 生产 Manager 保持 NOT_ACTIVE；未触发 Jenkins；未做 Argo/GitOps 变更；候选未部署（本轮末复查：运行中 Deployment 仍为 Index `sha256:489cb821…`）。
- 凭据红线：签名私钥只在 devops root 的 700 临时目录内解密使用、用后销毁（trap + shred），未写入任何证据/日志；Harbor 写入只用项目级 cosign-push robot 251（push+pull、仅 petclinic）；只读核查用 trivy-pull robot 250；未借用 Jenkins 生产 `harbor-creds`、未新建账号。

## 1. 候选字节与工具（devops，root 只读）
- Index 与两子 Manifest 原始字节自 Harbor 拉取，sha256 逐一断言等于钉死 digest（全过，`raw/stage.log`）；字节与 SBOM 包 `raw/` 内副本一致。
- 工具：devops `/usr/local/bin/cosign` v3.1.4，sha256 `ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2`，与平台 `scanner-tools.json` 钉死值一致。

## 2. Cosign 签名（devops，root 受控运行；脚本与日志在 `raw/`）
- 身份：`sops decrypt` bootstrap 签名包（age 密钥为既有 signing 密钥）到 700 临时目录；导出公钥与仓库 `infra/security/cosign.pub` **逐字一致**后才签名。
- 字节签名（证据层）：`cosign sign-blob --new-bundle-format=false --use-signing-config=false --tlog-upload=false` 对 Index/双子 Manifest 确切字节签名（`raw/sign.log`）；验签正例 3/3 rc=0，负例 5/5 被拒（篡改清单、Index 签名配子清单、双架构互换、篡改签名、缺签名；`raw/verify.log`）。
- Registry 签名（Harbor 附属物）：以 robot 251 的 docker config 执行 `cosign sign --use-signing-config=false --tlog-upload=false` ×3，rc=0；`cosign verify`（cosign.pub）×3 rc=0（`raw/registry-verify*.log`）。cosign v3 实际落盘形式为 **OCI referrers + sigstore bundle**（bundle manifest：Index `sha256:6e923714…`、amd64 `sha256:b9ccda8a…`、arm64 `sha256:4f52499a…`）。
- **旧式 `.sig` 标签补推**：现行 Kyverno 策略不消费 referrers（候选在仅有 referrers 时被拒 `no signatures found`，实测），而流水线时代的签名均为旧式标签。故按 Harbor 内现存流水线样本（运行中 Index 的 `.sig`：config/payload 模板、层 mediaType `application/vnd.dev.cosign.simplesigning.v1+json`、注 `dev.cosignproject.cosign/signature`）的确切格式为三 digest 构造 payload（SimpleSigning，docker-reference=`core.harbor.domain/petclinic/petclinic`）、以同一平台身份 sign-blob 后经 Registry v2 API 以 robot 251 推入（`raw/legacy-sig.log`）：三标签 PUT 均 201，sig manifest digest 分别为 Index `sha256:3f51e807…`、amd64 `sha256:ea06ff54…`、arm64 `sha256:c2531a16…`。

## 3. Kyverno 签名准入正反例（隔离命名空间，真实执行；`raw/kyverno-dry.log`、`raw/dryrun-*`、`raw/real-*`）
策略为集群现行 `ClusterPolicy/devsecops-signed-images`（Enforce），未新建未修改：
- 已签名 fixture（build 270，`sha256:86ddc3e1…`）：dry-run rc=0 放行；真实创建 rc=0，随即删除。
- 未签名 fixture（`sha256:d65f8d7f…`）：rc=1 被拒（`no signatures found`）。
- 错钥 fixture（`sha256:4a4c9aab…`）：rc=1 被拒。
- **候选本身**：补推旧式标签前 rc=1 被拒（`no signatures found`）；补推后 **dry-run rc=0、真实创建 rc=0（pod/b4-candidate），随即删除**。
- 清理：测试 Pod 全删，`devsecops-supply-chain` 命名空间复查为空。

## 4. Provenance 证明链与发布决定（Mac 生成 → devops 签名 → Mac 封存）
- `artifact/provenance-chain.json`（sha256 `ce66b134764bc64ee838d2d939b170c03cddd99997ca4405f0d6655aaf5076d0`）：关联构建来源（build #7 build.xml 证据 + 双 attestation vcs:revision=修复提交）+ 本轮复扫（双架构 HIGH=0）+ SBOM 绑定封存锚 + 签名三形式与 Kyverno 用例 + 发布门 G4。
- `artifact/release-decision.json`：与 Index digest 绑定的发布决定，**status=APPROVED、blockers=[]**；明示不等于部署、生产切换需另行审批；`supersedes` 指向旧候选（仅记录层，其 Harbor 本体未动）。
- 两份文档均按平台既有模式 sign-blob + verify-blob（`raw/signdocs.log`、签名记录 `artifact/signature-*.json`）。

## 5. 封存与独立验证
```sh
cd evidence/2026-11-13/supply-chain-b4-step2
node build-step2-artifact.mjs   # 重建前先删 artifact/ 与 binding-anchor.json（artifactStore 拒绝已存在目录）
node verify-step2.mjs           # 期望 20 项全 PASS、exit 0（实测 raw/verification-output.log）
```
验证含：seal 校验、记录 digest、决定→证明链 sha 链接、APPROVED 与范围断言、五份签名用纯 Node ECDSA 离线复验、原始字节 digest 断言、SBOM 包锚点交叉链接、Kyverno 候选放行记录一致性、旧候选 supersede 指针；负例：篡改 Index 字节、架构互换、文档篡改、seal 篡改，全部被拒。
封存锚：sealDigest `1f20385a75c7eb98f4e2d39a744dcbb99e292d7bd09eb10e3666be7ddb923af6`；chainDigest `ce66b134…`；decisionDigest `fe4a7e0710e0651b5090d2ff18f91f5b4df1a7e64075f077e46859847187d22f`。

## 6. 回归（纯净克隆，基线口径，同全量轮）
```sh
git clone ~/code/petclinic-platform-20261011 /tmp/b4clone && cd /tmp/b4clone && git checkout fix/security-manager-plugin-switches
node --test infra/security/manager-v2/*.test.mjs                                            # 基线 180/180
node --test infra/security/manager-v2/*.test.mjs infra/security/manager-v2/view/*.test.mjs   # 基线 202/202
node --test infra/security/*.test.mjs infra/observability/*.test.mjs                         # 基线 147/147
node --test <consumers 测试文件>                                                              # 基线 114/162（48 败为既有基线集）
```
实测日志 `raw/suiteA-manager-v2.log`、`raw/suiteB-manager-v2-view.log`、`raw/suiteC-infra.log`、`raw/suiteD-consumers.log`。本轮零源码改动（仅新增证据目录），回归为基线复测性质。
