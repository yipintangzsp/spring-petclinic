# SOPS V2 — REPRODUCE

对象：插件 `sops`（secrets-gate 校验，冻结 Policy 适配器
`infra/security/policy/sops-evidence.mjs` 的 sopsFacts/sopsDecision）。

## 机制

`sops-real.mjs` 经受限 SSH（`security-sops@192.168.1.58`，Mac 侧专用密钥
`~/.ssh/security-manager-v2-sops`，0600）驱动 devops 上 root 所有的固定入口
`/var/lib/security-sops/entry.py`（authorized_keys `restrict` + forced command
`setpriv --no-new-privs python3 entry.py`，协议
`validate-v1 <projectId> <runId> <caseId>`，调用方不能传任何文件、密钥、
目标或 sops 参数）。

入口每次运行在本运行工作目录内生成一次性 age 密钥对，用钉版 sops 3.13.3
（sha256 `53b0abac…94d77`）/ age 1.3.2（sha256 `41b07235…fc94f`）为四个冻结
secrets-gate 目标（petclinic/petclinic-db、petclinic/rabbitmq-client、
petclinic/petclinic-harbor-pull、devsecops-system/kyverno-registry-pull）
加密合成 Secret 夹具，执行门禁观察流（decrypt → scope → live compare →
fixture-store apply → re-read → fixture ACL 权限矩阵 → 脱敏报告），返回观察
packet；测试私钥在返回前粉碎、整个工作目录删除（cleanup=VERIFIED 才报）。
事实形状喂冻结适配器：全检查通过才 PASS，否则 FAIL；runner 不自算决策
（oldDecision 为冻结引擎对同一 fact 的判定，Core 单次复评比对）。

生产集群、生产密文、生产 age 密钥从不触碰：验证面是文件夹具存储
（runtimeFacts.storeModel=FILE_FIXTURE_STORE，rbacModel=FIXTURE_STORE_ACL，
此等价面由冻结的 SOPS 兼容性评审确立）。夹具值全部是合成公开标签，无真实
秘密材料；本流程不涉及任何私钥的读取或落盘。

## 中断点诊断（首轮失败，raw/ 原件未改）

首轮（2026-11-13 01:50）五案 ERROR / SOPS_TRANSPORT_ERROR
（stage=RESTRICTED_SSH_RUNNER、scannerStarted=false），仅 data-drift 成功。
devops auth.log 实测：五个失败会话各持续约 20.3s——正好等于入口 run_tool
默认超时 20s。入口在剥离环境（无代理）下执行 `sops --version`，其在线版本
检查偶发挂起超过 20s；`subprocess.TimeoutExpired` 未被入口捕获（只捕获
RuntimeError），进程以 traceback 退出、无 JSON 输出，runner 据此映射为
TRANSPORT_ERROR。成功的那一案（16.6s）恰好在超时内完成同一检查。用户、
forced-command、工具钉版哈希本身均已建成且正确（本线实测复核：
security-sops uid/gid 1006、entry.py root 所有 444、sops/age/age-keygen
sha256 与 projects.json 逐一一致）。

## 入口修复（devops 侧，/var/lib/security-sops/entry.py）

sha256 演进：`3701907c…e188`（首轮版）→ `bc6f3bd3…cf5488`（超时修复）→
`7f9c9d85…87d`（现行版）。安装方式同首轮：
`sudo install -o root -g root -m 444 <新版> /var/lib/security-sops/entry.py`；
旧版备份在 devops `/tmp/sops-entry.py.orig-20261113`。

1. `sops --version` 探测改 timeout=6，任何失败回退到入口开头已单独验过的
   钉版 sha256（工具身份的权威依据），不再让版本检查的网络挂起杀死整轮。
2. 顶层新增 `subprocess.TimeoutExpired` 处理：返回 JSON
   `{error: EXECUTION_TIMEOUT, stages}` 而非 traceback。
3. tampered-ciphertext 篡改改法：原来整文件中点翻一个字节，随机密文下会
   偶发破坏 JSON 结构（cipherFacts 的 hasMac 变 false，被 runner 校验拒为
   RUNNER_REPORT_ERROR——重跑尝试 1 实测）；改为只翻加密载荷内一个 base64
   字符，JSON 结构、sops 元数据与 MAC 字段保持完整（hasMac=true、
   recipientCount=1），decrypt 必因 AES-GCM/MAC 校验失败（实测 exit 25）。

## 复跑

```
node --test infra/security/manager-v2/sops-real.test.mjs        # 9/9
node evidence/2026-11-13/sops-v2/run-driver-rerun.mjs           # 最终轮，产出 raw-rerun/
bash evidence/2026-11-13/sops-v2/grafana-check.sh               # 在 devops 会话内执行
```

证据布局：`raw/` = 首轮失败原件（未改写）；`raw-rerun-attempt1/` = 超时修复
后第一轮重跑（tampered 案 RUNNER_REPORT_ERROR，其余全对，compliant 的 Loki
已 DELIVERED/VERIFIED）；`raw-rerun/` = 最终全量重跑（六案全对、Loki 两案
DELIVERED+VERIFIED、Grafana 回查 grafana-loki.json 两案 matched=1）。
run-driver-rerun.mjs 与 run-driver.mjs 的差异只有两处：输出目录
raw-rerun 与 summary 文件名 core-driver-summary-rerun.json。

## 用例（最终轮，runId 见 verification.json）

sops-lab：compliant PASS；tampered-ciphertext / wrong-key /
plaintext-masquerade / data-drift 均 COMPLETED/FAIL（oldGate 与 Core 求值
全等）；sops-cleanroom compliant PASS（第二项目）；plugin-off /
master-off DISABLED、evaluationCount=0；跨项目三拒绝（双向 targetId 错配、
用例泄漏）均在本地零 SSH 拒绝 SOPS_PROJECT_NOT_AUTHORIZED。

## 回归

sops-real 9/9；manager-v2 全集 176/176（基线 167 + sops 9）；
infra/security/*.test.mjs + infra/observability/*.test.mjs 147/147；
consumers 114/162、48 败与既有基线同因（夹具老化 + 样例目录 EEXIST），
无一涉及 sops。

## 共享文件接线增量（未提交，G-SOPS2）

改前快照在 `protected-before/`。以下为相对快照的 sops 专属 hunk（同文件
另有 W3/W4/W5 未提交增量纠缠，按 Falco/Provenance 先例留工作区）：

- registry.mjs：新增 `realSops` 校验常量行；`real` 或链与 timeout 三元链
  各加 realSops / `realSops?120000`；文件尾新增 `realSopsRegistry()` 导出块。
- core.mjs：新增 `import {executeRealSops} from './sops-real.mjs';`；
  dispatch 三元链加 `sops-real` 分支。
- consumers/loki.mjs：singlePluginId 白名单加 `'sops'`。
- consumers/loki-event-v1.json：plugins 数组加 `"sops"`。

本线已提交：sops-real.mjs、sops-real.test.mjs、sops/projects.json、
sops/runner.json 与本证据目录。

## 缺口

- G-SOPS1（Web UI）：view 未接 sops；Core/能力层已验，sopsUiCase 已备
  （clean→compliant、controlled-finding→tampered-ciphertext）。归 W12 统一处理。
- G-SOPS2（接线提交）：见上；不挡运行（工作区状态已全量实测），挡提交完整性。
- 武装文件 `.devsecops/security-view-sops-linux-v1.json` 保持
  {enabled:true, consumed:false}（与 kyverno/sonar/trivy/zap 先例一致），
  归 W13 收口检查项。
