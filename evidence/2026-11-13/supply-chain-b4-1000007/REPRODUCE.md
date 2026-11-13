# 复现说明 — 供应链 B4 全链重锚：新候选 0.10.0-ci-1000007（2026-11-13）

对象：Harbor `petclinic/petclinic` 候选 OCI Index `sha256:a8e800ef6a66081eebbd2a620f24f42c16b36dc33860bdf83d934e63a9ffb072`
（amd64 子 Manifest `sha256:5bed9d1ddeae0a136577d55e72cf6cfe9f57d55d0390cdc15c8a98bc50c02169`、arm64 子 Manifest `sha256:3cc885b3cbe2709ef7aaf384382477a33d996cfd4125d4489e7d3446793c6e57`，另含 2 个 buildx provenance attestation manifest）。
背景：U2 修复提交 `318d479fb458ff229d0e10ed99ae7317f7427625`（apt/libapt-pkg7.0 → 3.2.1ubuntu0.1，CVE-2026-109518）经 Jenkins `petclinic-candidate-build` #7 构建成功（前置：QEMU 仿真层修复，见执行记录 §16–§22）。
锚点：`binding-anchor.json`（两套封存包的 sealDigest 与记录 digest 在带外固定于此文件；验证只认它）。
本轮按第一步先例**不提交**：本目录全部文件为未跟踪新增。

## 0. 前置
- Mac 仓库 `~/code/petclinic-platform-20261011`，分支 `fix/security-manager-plugin-switches`；Node 用 `/opt/homebrew/bin/node`。
- Harbor 只读拉取（项目 robot 只读凭据，值不入任何文件）；生产 Manager 保持 NOT_ACTIVE；未动生产。

## 1. 漏洞库刷新（复扫前置，官方 GHCR 路线）
- 受控缓存 `/var/lib/security-trivy/db-cache` 的主库 NextUpdate 已过（2026-11-13T07:01Z），先刷新：Mac 从官方 GHCR 下载 `trivy-db:2`（manifest `sha256:9d570840823a4fbd0004ccdd251e89dd59d91aa093df55bc541d493eca406ad0`、层 `sha256:fd406c50cad6892a16b258bef67be31ebfd4ddfb00da80ce869b461e73116d4f`）与 `trivy-java-db:1`（层 `sha256:d1ef50b7b265c67362f7d61a22d7dcc507346b1252e2173d046edd5ddcb26fd6`），层摘要与文件 SHA256 双端校验后经局域网送 devops 装入（root:security-trivy、文件 440／目录 750，旧库改名为 `db.bak-20261113-b4`、`java-db.bak-20261113-b4` 留作回滚，链条收尾后清除）。
- 装后元数据：db UpdatedAt `2026-11-13T07:00:07Z`、NextUpdate `2026-11-14T07:00:07Z`；java-db UpdatedAt `2026-11-13T01:08:15Z`、NextUpdate `2026-11-16T01:08:15Z`。文件哈希：trivy.db `324ef75b4ba84ec45caf6e427bb3c7f57732beae1933afc6cbafd8fe1a85f441`；java-db `751b0549b469b1dd47b58d417e0a4e8559d28e75f11ac8d8a062af01c476e075`。

## 2. 双架构受控复扫（devops，security-trivy 身份）
- 工具：平台钉死 Trivy 0.76.2（sha256 `7844c385…` 与钉死值一致）；命令与 SBOM 生成同一受控启动器（`--insecure --cache-dir /var/lib/security-trivy/db-cache --skip-db-update --skip-java-db-update`，目标钉死子 Manifest digest；robot 只读拉取）。
- 首跑因 trivy 自动加载 CWD 下无权读取的 trivy.yaml 秒退，启动器改为先 cd 到受控工作目录后通过（见绑定回执 attempts）。
- 结果（`raw/scan-amd64.json` sha256 `eb68772865c3102360279d4baa169a9eb9ba15a01cd8552abb0ae517dc3b0a80`；`raw/scan-arm64.json` sha256 `93c9eb555560206ccf1ea9aa6a0492b4bb9995ca2a0302a76438e1030aba21b7`）：双架构 **CRITICAL 0 / HIGH 0 / MEDIUM 82 / LOW 4**；**CVE-2026-109518 双架构均不在**；apt 与 libapt-pkg7.0 检出版本双架构均为 **3.2.1ubuntu0.1**。MEDIUM 较旧候选（58）多系漏洞库刷新至 2026-11-13 所致，验收口径（HIGH=0＋目标 CVE 不在＋修复版本在位）满足。

## 3. 来源材料核查（只读）
- devops 上以 robot 凭据 GET Index 与子 Manifest 原始字节，逐一断言 sha256 与目标 digest 相等（`raw/index.json`、`raw/manifest-*.json`、config 见 `raw/config-*.json`）。
- Index 内两份 attestation 的 in-toto 载荷（`raw/att-*.intoto.json`）：subject 分别精确指向 amd64/arm64 子 Manifest（带 platform 参数），`vcs:revision=318d479fb458ff229d0e10ed99ae7317f7427625`。
- Jenkins 构建记录：`petclinic-candidate-build` #7 的 build.xml（控制器 PVC）实读 `<result>SUCCESS</result>`、SCM revision = 修复提交、startTime 2026-11-13T07:46:22.697Z、duration 344,809 ms。本构建**没有 DSSE 签名声明**（旧候选的声明来自单独的声明作业），来源层据实以构建记录＋buildx attestation（未签名副本）成立，评估记录中已注明。
- 两架构分别定位含 `app/app.jar` 的层并解出 jar（`raw/jar-facts.txt`）：两架构 jar sha256 同为 `be01f8ce2db70b3a5f4f8dcff9fe185a59cccbfe402ee0ac8ad378ab01dca401`（78,612,070 字节）；jar 内嵌构建期 SBOM `raw/embedded-sbom.json` sha256 `b0a9ab3d854212e8ff6ace34cfd683775ce32cac955b9d41e038dca78dc2b3f3`——**与旧候选逐字相同**，与「仅 OS 包钉版、应用依赖未动」的修复内容吻合。

## 4. 描述性镜像 SBOM 生成（受控运行，devops）
- 正式路径不可用（同第一步）：`sbom-real` 只对固定 POM fixture；且 SBOM Policy 只收 CycloneDX 1.6、生成物为 1.7（**U6 未决，本轮不改 Policy 不改口径**）。降级受控运行：security-trivy 身份、钉死 Trivy 0.76.2、`trivy image --insecure --format cyclonedx` 对子 Manifest digest 钉死生成，暂存 Mac `/tmp/sbomstage-b4/` 后 sha256 与生成事实（`/tmp/sbomstage-b4/facts.txt`）逐一对账。
- 产物：amd64 SBOM sha256 `208835ab54e988fb2e6201579c37ebf26b17d6c93c1720f11582c94a4ed2f7f3`（485,450 字节，271 组件）；arm64 sha256 `9831f9aa3ca6805c54c8032a3d8e2758852affd0a95d70d1a72526012eaba018`（487,256 字节，271 组件）；specVersion 均为 1.7。

## 5. 封存两个工件包（平台 artifactStore + summary-v2 codec，未新造格式）
```sh
cd evidence/2026-11-13/supply-chain-b4-1000007
node build-binding-artifact.mjs      # 输入 /tmp/sbomstage-b4 的两份 SBOM 与 facts.txt → artifact/ + build-output.json
node build-provenance-artifact.mjs   # 输入 raw/ 来源材料（复扫计数由脚本从 raw/scan-*.json 重算） → artifact-provenance/ + provenance-build-output.json
# binding-anchor.json 取两份 build-output 的 sealDigest / bindingDigest / receiptDigest / provenanceSealDigest / assessmentDigest 按第一步同结构写入
```
- `artifact/`：两份镜像 SBOM 原文 + `sbom-binding.json`（绑定记录，内嵌复扫验收摘要）+ `sbom-generation-receipt.json`（受控运行回执），sealDigest `ce3c1ff04941a7041e70125ae6ce8f92caaf4ac0146678cc4c033dcbf06323e1`。
- `artifact-provenance/`：构建期 SBOM 原文 + 两份 attestation 原文 + `rescan-summary.json` + `provenance-assessment.json`（逐关系判定），sealDigest `fffe57250939cae43ff9dbd22ce6f62cddcb53caa902597d619bff7aec3540d0`。

## 6. 独立验证（正例 + 全套负例）
```sh
node verify-sbom-binding.mjs   # 期望全 PASS、exit 0（实测输出 raw/verification-output.log）
```
正例：双封存包 seal、绑定/回执/评估 digest、双架构 SBOM sha 与 subject（bom-ref/ImageID/serial）、Index 成员与平台配对、构建期 SBOM sha、attestation subject 配对、**attestation vcs:revision = 修复提交**、**复扫报告重算（HIGH/CRITICAL=0、目标 CVE 不在、修复版本在位、计数与评估记录一致）**。
负例（必须全被拒绝）：N1 SBOM 篡改一字节；N2 错误 Index digest；N3A 双架构 SBOM 互换；N3B 拿 Index digest 冒充子 Manifest；N4 绑定记录篡改；N5 跨项目 SBOM 串用（java-sbom-demo-b）；N6 Index 成员被改；**N7 跨候选串用（旧候选 build #2 的 SBOM 冒充本候选——sha 不同且 subject 拒绝）**。
注记：验证脚本首跑 P13 因计数对象 JSON 键序比对过严误报 2 项（数值逐项相同、报告 sha 对版），已改逐级数值比对后全过；证据本身未变。
