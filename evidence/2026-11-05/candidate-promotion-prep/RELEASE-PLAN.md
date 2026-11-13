# PetClinic 候选镜像晋升准备（未授权发布）

**NO — 审计通过，发布批准缺失。** `petclinic-ci #270` 以 `audit-only` 运行，候选绑定的 V1 Gate SUCCESS，Trivy High/Critical=0/0；原构建和安全验收 attestation 已用固定公钥复核。#270 未产出 `candidate-sbom.json`、`approval-signing.json` 或 `approved-release.json/.sig`；现行 Cosign 镜像签名标签 HEAD 404。既有晋升入口拒绝缺少同次构建签名批准的发布。不能用 #270 PASS、构建 attestation 或本补丁替代批准。

GitOps 实际源为 GitLab `root/petclinic-platform` 的受保护 `main`，基准 `340ef4b8c74e3c2a5820da8d98b0f134283bb8d9`。仅修改 `k8s/production/petclinic.yaml` 的 `Deployment/petclinic` → 容器 `petclinic` → `image`。`promotion.patch` 使用实际基准文件验证，只替换一行，临时目录反向应用后字节一致。当前保留 3 副本、RollingUpdate `maxSurge=0 / maxUnavailable=1`、三类探针和 CPU/内存 requests `100m/512Mi`、limits `500m/768Mi`；不改 Service、Ingress、数据库或调度。

| 用途 | OCI Index | Linux ARM64 子 Manifest | Linux AMD64 子 Manifest |
|---|---|---|---|
| 候选 `0.10.0-ci-1000002` | `sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55` | `sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42` | `sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94` |
| 当前 / 回滚 | `sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137` | `sha256:956525e00136b8a553564a2a8ef2be4347b791c1e938499c25e3588eb5ad14f2` | `sha256:ab79439f86cef8a02bb7103d07736397c7c6589c938bcfebf91f18b615480508` |

已用 Harbor pull scope 校验上述 Manifest 原始字节 Digest，27 个去重配置/层 HEAD 均为 200。两 Index 在 `devops` 现用镜像入口 HEAD 200。三节点 Ready 且无压力条件；现有 selector 只允许 `devops`（ARM64）承载此 Deployment。两 AMD64 节点不参与本轮晋升，无冷拉测试，未读取拉取 Secret 值。当前 PetClinic 3/3、3 个 Ready Endpoint、HTTP 200、Argo Synced/Healthy。

实际发布须另行批准。授权需覆盖既有 `petclinic-ci` 的候选 Gate 及同次签名批准、向 Harbor 写入既有流程所需签名附件、使用既有身份向受保护 `main` 推送，以及随后的 Argo 自动同步和 Kubernetes 滚动更新。现有入口会提交 `release-approvals/petclinic-build-<新构建号>.json` 和 `.sig` 作为批准证据；它们不改变部署配置，但必须包含在批准范围。`dry-run` 同样会先签名，不属于本轮只读操作。

1. 执行前重新确认 `main`、Argo revision、当前 Digest 和健康与上述基准一致，确认无并行发布。任一不符即停止，不强推。
2. 获批后复用 `petclinic-ci`，固定现有安全源码 `9a78cc89f22fa98fb1ffcc43e2ae279299471793`、`AUDIT_CANDIDATE_IMAGE=core.harbor.domain/petclinic/petclinic@sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55`、`ENABLE_IMAGE_BUILD_PROVENANCE=true`、`PROMOTION_ACTION=deploy`。`BUILD_PROVENANCE_EXPECTATION={"commit":"9a78cc89f22fa98fb1ffcc43e2ae279299471793","repository":"http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git","builder":"http://jenkins.devops.local/job/petclinic-candidate-build","buildNumber":"2"}`。保持其他可选功能关闭。使用现行 Gate、SBOM、签名批准与晋升入口；不手工应用本补丁到 main，不绕过任何阶段。
3. 记录 Jenkins 结果、签名批准与实际 GitOps Commit。等待 Argo 同步该 Commit 并 Healthy；验证 Deployment 滚动完成、3/3 Ready、业务 HTTP 200。比对所有 Pod 的实际 Image ID：应指向候选 Index 或该节点架构的候选子 Manifest；若运行时展示配置 Digest，则用平台子 Manifest 的 `config.digest` 交叉验证。刷新只读证据后，Overview 才标 `MATCHED`。
4. 晋升后若失败，使用既有流程对本次晋升 Commit 做 GitOps `revert`，恢复旧 Digest；回滚 Commit 保留既有跳过 CI 标记。自动回滚只在远端 HEAD 仍为该晋升 Commit 时执行；发现并发提交则停止并检查，不覆盖他人变更。确认 Argo 同步回滚 Revision、Deployment 恢复旧镜像、3/3 Ready、HTTP 200、Pod 实际 Image ID 对应旧 Index/子 Manifest。不得直接用 `kubectl set image` 或 `rollout undo`。

本轮没有执行签名、启动构建、冷拉、推送、Sync、Rollout 或回滚。页面 HTTP 200，仍显示 `NOT_DEPLOYED`。
