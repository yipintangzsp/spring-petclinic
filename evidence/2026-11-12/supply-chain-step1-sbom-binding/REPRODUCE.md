# 复现说明 — 供应链第一步：SBOM → 镜像 Digest 可信绑定（2026-11-12）

对象：Harbor `petclinic/petclinic` OCI Index `sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55`
（amd64 子 Manifest `sha256:2bd9c1c4…`、arm64 子 Manifest `sha256:06a51570…`，另含 2 个 buildx provenance attestation manifest）。
锚点：`binding-anchor.json`（两套封存包的 sealDigest 与记录 digest 在带外固定于此文件；验证只认它）。

## 0. 前置
- Mac 仓库 `~/code/petclinic-platform-20261011`，分支 `fix/security-manager-plugin-switches`，HEAD `b36b7554`；Node 用 `/opt/homebrew/bin/node`。
- 本轮按升级口径**不提交**：本目录全部文件为未跟踪新增，工作区他人未提交改动未触碰。
- Harbor 全程只读拉取（项目 robot 只读凭据，值不入任何文件）；未触发 Jenkins、未重扫 Trivy、未签名、生产 Manager 保持 NOT_ACTIVE。

## 1. 来源材料核查（只读）
- devops 上以 robot 凭据 GET Index 与四个子 Manifest 原始字节，逐一断言 sha256 与目标 digest 相等（`raw/index.json`、`raw/manifest-*.json`、`raw/generation-transcript.log`）。
- 取两份镜像 config（`raw/config-*.json`）：构建历史含 `COPY target/spring-petclinic-4.0.0-SNAPSHOT.jar app.jar`；无 OCI revision 标签。
- 取 Index 内两份 attestation 的 in-toto 载荷（`raw/att-*.intoto.json`）：subject 分别指向 amd64/arm64 子 Manifest（带 platform 参数），`vcs:revision=9a78cc89f22fa98fb1ffcc43e2ae279299471793`，构建窗 2026-10-30 11:14:39–11:16:23 +08。
- `skopeo copy` 两架构到 devops 临时目录，定位含 `app/app.jar` 的层并解出 jar：两架构 jar sha256 同为 `9e8791f2362cec807f090ae38afbc368950370ef2e21b6a3d9974bc548a07702`（78,611,896 字节）；jar 内含 `META-INF/sbom/application.cdx.json`（构建期 SBOM，`raw/embedded-sbom.json`，sha256 `b0a9ab3d…`）与 `META-INF/build-info.properties`；MANIFEST.MF 声明 `Sbom-Location`。jar 的 build.time 与 pom 固定的 `project.build.outputTimestamp=2024-11-28T14:37:52Z` 一致（可复现构建常量，非墙钟记录）。

## 2. 构建来源证明离线复验（平台既有脚本，零改动）
```sh
git clone ~/code/petclinic-platform-20261011 /tmp/sbomclone && cd /tmp/sbomclone
git checkout fix/security-manager-plugin-switches   # HEAD b36b7554
cd evidence/2026-11-05/build-harbor-link
cp verified.json /tmp/verified-committed.json && rm verified.json
node verify.mjs        # 期望 exit 0；内部含错 commit / 错 digest 拒绝断言
diff /tmp/verified-committed.json verified.json   # 期望零差异（字节一致）
```
该脚本离线复验 DSSE 签名信封（构建声明：petclinic-candidate-build #2 ↔ commit 9a78cc89 ↔ 候选 Index digest；安全验证声明：petclinic-ci #270 ↔ 同一 Index），公钥取自源 commit 的 `infra/security/cosign.pub`。本轮实测 exit 0、再生文件与已提交记录字节一致（日志 `raw/provenance-link-reverify.log`）。

## 3. 描述性镜像 SBOM 生成（受控运行，devops）
正式路径不可用：manager-v2 的 `sbom-real` 执行器只对固定 POM fixture 生成 Maven 依赖清单（scope `APPLICATION_MAVEN_DEPENDENCIES_ONLY`），其 README 明示「不是完整容器镜像 SBOM」「fixture SBOM 不证明 Harbor 候选」。故降级为受控运行，脚本与事实在 `raw/gen.sh`、`raw/facts.txt`、`raw/generation-transcript.log`：
- 身份 security-trivy（uid 990），工具 `/var/lib/security-trivy/bin/trivy` 0.76.2，sha256 与平台钉死值一致（`7844c385…`）。
- 命令：`trivy image --insecure --format cyclonedx --cache-dir <work>/cache --skip-db-update --skip-java-db-update --timeout 10m core.harbor.domain/petclinic/petclinic@<子Manifest digest>`（`--insecure` 因内部自签名 Harbor，完整性由 digest 断言锚定；缓存以平台当日 db-cache 副本播种，未联网下载 DB）。
- 前两次失败（TLS 证书、Java DB 首次运行不能跳过下载）与处置均记录在 transcript。
- 产物暂存 Mac `/tmp/sbomstage/` 后 sha256 与生成事实逐一对账一致。

## 4. 封存两个工件包（平台 artifactStore + summary-v2 codec，未新造格式）
```sh
cd evidence/2026-11-12/supply-chain-step1-sbom-binding
# 重建前先删除已有 artifact/、artifact-provenance/、binding-anchor.json 与 build-output（artifactStore 拒绝已存在目录）
node build-binding-artifact.mjs      # 输入 /tmp/sbomstage 的两份 SBOM 与 facts.txt → artifact/ + build-output.json
node build-provenance-artifact.mjs   # 输入 raw/ 来源材料 → artifact-provenance/ + provenance-build-output.json
# 再生 binding-anchor.json：取两份 build-output 的 sealDigest / bindingDigest / receiptDigest /
# provenanceSealDigest / assessmentDigest 按现文件结构写入（本轮即如此生成）。
```
- `artifact/`：两份镜像 SBOM 原文 + `sbom-binding.json`（绑定记录）+ `sbom-generation-receipt.json`（受控运行回执），sealDigest `c0b526e1…`。
- `artifact-provenance/`：构建期 SBOM 原文 + 两份 attestation 原文 + 平台 build-harbor-link 记录副本 + `provenance-assessment.json`（逐关系判定），sealDigest `30a7e6cd…`。

## 5. 独立验证（正例 + 全套负例）
```sh
node verify-sbom-binding.mjs   # 期望 23 项全 PASS、exit 0（实测输出 raw/verification-output.log）
```
正例：双封存包 seal 校验、绑定/回执/评估记录 digest、双架构 SBOM sha 与 subject（bom-ref/ImageID/serial）、Index 成员与平台配对、构建期 SBOM sha、attestation subject 配对、两包交叉链接。
负例（必须全被拒绝）：N1 SBOM 篡改一字节；N2 错误 Index digest；N3A 双架构 SBOM 互换；N3B 拿 Index digest 冒充子 Manifest；N4 绑定记录篡改；N5 跨项目 SBOM 串用（java-sbom-demo-b 的真实 SBOM：sha 不同、subject 拒绝、跨包锚拒绝）；N6 Index 成员被改（digest 层拒绝）。

## 6. 回归（纯净克隆，基线口径）
```sh
cd /tmp/sbomclone   # HEAD b36b7554，不含工作区未提交改动
node --test infra/security/manager-v2/config.test.mjs infra/security/manager-v2/registry.test.mjs infra/security/manager-v2/core.test.mjs infra/security/manager-v2/runner.test.mjs infra/security/manager-v2/integration.test.mjs infra/security/manager-v2/trivy-real.test.mjs infra/security/manager-v2/view/origins.test.mjs infra/security/manager-v2/view/mac-budget.test.mjs infra/security/manager-v2/view/loki-delivery.test.mjs infra/security/manager-v2/observability/queries.test.mjs   # 期望 89/89
node --test infra/security/*.test.mjs infra/observability/*.test.mjs   # 期望 147/147（含 SBOM 插件回归面）
```
实测日志 `raw/suite1.log`、`raw/suite2.log`。
