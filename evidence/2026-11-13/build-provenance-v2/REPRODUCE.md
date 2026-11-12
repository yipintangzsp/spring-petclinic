# Build Provenance V2 — REPRODUCE

对象：插件 `build-provenance`（镜像构建来源声明核验，predicate
`https://devops.local/attestation/image-build/v1`）。

## 真实材料
- 历史签名 DSSE 信封：`evidence/2026-11-05/build-harbor-link/archived-proof.json`
  内 `.devsecops/build-attestation-envelope.json`（Jenkins
  petclinic-candidate-build #2 的签名构建声明：buildType
  `petclinic-maven-buildx-v1`、commit `9a78cc89…`、候选 Index
  `sha256:2fbaea65…`、jar/buildkit 锚、双平台）。archived-proof.json
  sha256 钉死 `3690e326…`（projects.json）。
- 公钥：`infra/security/cosign.pub`（sha256 `490c048d…`）。**只验签、未签名。**
- SBOM 交叉锚：step1 `binding-anchor.json`（sealDigest `c0b526e1…`）。

## 机制
`build-provenance-real.mjs` 自身以平台既有 `verifyEnvelope` +
`validateBuildStatement` 对真实信封执行真实核验（签名、subject、
source commit/repository、builder 身份/构建号、jar 与 buildkit 锚、
平台集、时间序），结果成形为冻结适配器 `buildProvenanceEvidence`
消费的版本化核验事实（phase=verify、exitCode 真实结局、artifacts
含核验报告与信封）。oldDecision 为冻结引擎判定，Core 单次复评比对。

## 复跑
```
node --test infra/security/manager-v2/build-provenance-real.test.mjs   # 9/9
node evidence/2026-11-13/build-provenance-v2/run-driver.mjs
bash evidence/2026-11-13/build-provenance-v2/grafana-check.sh          # devops 会话内
```

## 用例
historical-build PASS；wrong-commit / wrong-digest / tampered-envelope
均 exitCode=1 → COMPLETED/FAIL；plugin-off / master-off DISABLED 零求值；
跨项目三拒绝（BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED）。

## 共享文件接线增量
与 provenance-v2/REPRODUCE.md 所列同一批增量（两插件共用一次接线），
改前快照在本目录 `protected-before/`。
