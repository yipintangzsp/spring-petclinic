# Provenance V2 — REPRODUCE

对象：插件 `provenance`（安全验证来源声明验证，predicate
`https://devops.local/attestation/security-validation/v1`）。

## 真实材料
- 历史签名 DSSE 信封：`evidence/2026-11-05/build-harbor-link/archived-proof.json`
  内 `.devsecops/attestation-envelope.json`（Jenkins petclinic-ci #270 对候选
  Index `sha256:2fbaea65…` 的签名安全验证声明，commit `9a78cc89…`）。
  archived-proof.json sha256 钉死 `3690e326…`（projects.json）。
- 公钥：`infra/security/cosign.pub`（sha256 `490c048d…`，与源 commit 一致）。
  **只用公钥验签；未读、未用任何私钥；未做任何新签名。**
- SBOM 交叉锚：`evidence/2026-11-12/supply-chain-step1-sbom-binding/binding-anchor.json`
  （sealDigest `c0b526e1…`，subject indexDigest 与声明 subject 一致性核对）。

## 机制
`provenance-real.mjs` 把真实材料组装成冻结 Policy 适配器
`provenanceParent` 消费的回放观测：cosign verify-attestation 命令观测
携带真实归档信封原文、工具清单观测为真实 scanner-tools.json、
`.git-sha`/公钥文件观测为真实值；DSSE 验签与身份校验由适配器自带的
`verifyEnvelope`/`validate` 在 Policy 求值内真实执行。oldDecision 为冻结
引擎对同一 fact 的判定，Core 单次复评比对。

## 复跑
```
node --test infra/security/manager-v2/provenance-real.test.mjs   # 9/9
node evidence/2026-11-13/provenance-v2/run-driver.mjs            # 需 Loki 隧道在位（投递段）
bash evidence/2026-11-13/provenance-v2/grafana-check.sh          # 在 devops 会话内执行
```
run-driver 产出 `raw/core-driver-summary.json` 与各案 artifactStore 封存副本。

## 用例
historical-candidate PASS；wrong-commit / wrong-digest / tampered-envelope
均 COMPLETED/FAIL（真实被拒）；plugin-off / master-off DISABLED 零求值；
跨项目三拒绝（用例泄漏到 cleanroom、targetId 错配、未知项目）。

## 共享文件接线增量（未提交，G-P2）
- registry.mjs：realProvenance/realBuildProvenance 校验条件 + 两行 `real` 或项；
  文件尾 realProvenanceRegistry()/realBuildProvenanceRegistry()。
- core.mjs：两行 import；dispatch 三元链加 provenance-real/build-provenance-real 两支。
- consumers/loki.mjs：counts 的 NOT_A_VULNERABILITY_SCANNER 名单加两插件；
  singlePluginId 白名单加两插件。
- consumers/loki-event-v1.json：plugins 数组加 "provenance","build-provenance"。
改前快照在 `protected-before/`（与 build-provenance-v2 各一份）。
