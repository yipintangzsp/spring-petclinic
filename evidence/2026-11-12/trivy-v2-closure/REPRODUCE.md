# 第三方独立复核步骤 · Trivy V2 Closure (2026-11-12)

所有原始输出保存在本目录 `raw/`，报告与 JSON 只引用不替代。仓库分支 `fix/security-manager-plugin-switches`，基线提交见 `../status.json` 与各提交哈希（17ca30e4、9dd706c4、62fe8359、9177c21f、6f668a52、8c2daa5b 及本证据提交）。

## 1. 契约测试（Mac，仓库根目录）
在整仓一次性副本中运行（避免个别套件向工作树写产物）：
```
node --test infra/security/manager-v2/config.test.mjs infra/security/manager-v2/registry.test.mjs infra/security/manager-v2/core.test.mjs infra/security/manager-v2/runner.test.mjs infra/security/manager-v2/integration.test.mjs infra/security/manager-v2/trivy-real.test.mjs infra/security/manager-v2/view/origins.test.mjs infra/security/manager-v2/view/mac-budget.test.mjs infra/security/manager-v2/view/loki-delivery.test.mjs infra/security/manager-v2/observability/queries.test.mjs
node --test infra/security/*.test.mjs infra/observability/*.test.mjs
```
期望：86/86、147/147。原始输出：`raw/contract-manager-v2.log`、`raw/contract-runtime-facts.log`。
基线异常（与本轮无关）：`node --test infra/security/manager-v2/consumers/*.test.mjs` 中 loki HTTP/REPLAY 用例以 LOKI_TIMESTAMP_OUTSIDE_WINDOW 失败（30/156），原始输出 `raw/contract-consumers-baseline.log`。

## 2. Web/API 开关验收（Mac）
```
node infra/security/manager-v2/view/control.mjs start
node raw/repro-api-acceptance.mjs        # 开关关/开两场景，脚本在本目录
printf '{"enabled":true}\n' > .devsecops/security-view-trivy-linux-v1.json   # 操作员一次性武装（0600）
node raw/repro-formal-attempt.mjs        # 武装正式尝试
rm .devsecops/security-view-trivy-linux-v1.json
node infra/security/manager-v2/view/control.mjs stop
```
期望：关→DISABLED/PLUGIN_DISABLED 零求值；未武装→BLOCKED/TRIVY_EXECUTION_NOT_ARMED；武装→READY 且运行 BLOCKED/CREDENTIAL_EXPIRED_BLOCKED（凭据未续期前）。原始转录：`raw/web-acceptance.log`；两次武装尝试的封存记录副本：`raw/run-web-eb7c1ac0-*/`、`raw/run-web-7f701cf6-*/`（可按 candidate-seal.json 自行验摘要）。

## 3. 受限入口探针（Mac，专用密钥，与 Adapter 相同参数）
```
/usr/bin/ssh -F /dev/null -T -n -i ~/.ssh/security-manager-v2-trivy -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o HostKeyAlias=192.168.1.58 security-trivy@192.168.1.58 'bogus'
/usr/bin/ssh -F /dev/null -T -n -i ~/.ssh/security-manager-v2-trivy -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o HostKeyAlias=192.168.1.58 security-trivy@192.168.1.58 'scan-v1 trivy-candidate web-11111111-2222-3333-4444-555555555555'
```
期望：`COMMAND_REJECTED`；第二条在资源窗口正常时为 `CREDENTIAL_EXPIRED_BLOCKED`（DB 已刷新），负载高时可能先返回 `RESOURCE_BUDGET_BLOCKED`（门禁按设计生效，非故障）。

## 4. DB 工件核验（任意机器）
- 官方清单原件：`raw/ghcr-trivy-db-manifest.json`（sha256 应为 69f786ce825ea62439875b067d2ba0aa91208354189e4289e047b986275fbc7e）、`raw/ghcr-trivy-java-db-manifest.json`（91f7488e5afee003ff19a0ca49bbd889eaa911bfde4279d37288f7a540a061c5）；也可对 ghcr.io/aquasecurity/trivy-db:2 与 trivy-java-db:1 重新 `skopeo inspect --raw` 比对。
- 服务端现状原始捕获：`raw/devops-state.log`（含 db-cache 清单、四文件 SHA256、metadata 原文、凭据到期字段、一次性标记缺失、工具 SHA256、两次 kubectl 节点观察）。
- 已安装 metadata 原件副本：`raw/db-metadata.json`、`raw/java-db-metadata.json`。

## 5. 代码坐标
见 `evidence-coordinates.json`（逐项列文件路径、行号与提交哈希）。
