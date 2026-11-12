# 复现步骤 · Falco G-F2 采集身份专属受限 uid（2026-11-13，W8）

仓库分支 `fix/security-manager-plugin-switches`；feat 提交见 verification.json 的 codeCommit。
本轮只收窄缺口 G-F2：Falco 采集从「devops 操作员 zhang 经 sudo kubectl」改为
「专属受限 uid security-falco（1007）+ SSH forced-command 单入口 collect-v1 +
专用 SA security-falco-collector 最小 RBAC」。冻结 falcoParent Policy 与分类口径一字未改；
G-F1（Policy FAIL 正例）未碰、G-F3（Web UI）归 W12。

## 1. 盘点（collector 调用 → RBAC 折算）

旧 collector.mjs 的全部集群操作（sudo -n kubectl 固定 argv）：

| 操作 | 资源/动词 | 范围 |
|---|---|---|
| `get pods -l app.kubernetes.io/name=falco` | pods get/list | devsecops-system |
| `get ds platform-falco` | daemonsets get（resourceNames=platform-falco） | devsecops-system |
| `logs <sensor-pod> -c falco` ×3（--tail / --since-time） | pods/log get | devsecops-system |
| `get pods`（workloads） | pods get/list | petclinic |
| `get node devops` | nodes get（resourceNames=devops） | cluster |
| `fetch http://<podIP>:8765/healthz` | 非 kubectl，入口内直连 Pod IP | — |

RBAC 清单即 rbac.yaml：SA security-falco-collector（devsecops-system）+ 同名
Role/RoleBinding（devsecops-system）+ petclinic 的 security-falco-workload-reader
Role/RoleBinding + ClusterRole/ClusterRoleBinding security-falco-node-reader。
无 secrets、无写动词、无其他命名空间。can-i 与直连尝试留证见 raw/identity-evidence.txt
（注：can-i 无资源名查询匹配不了 resourceNames 授权、且对 pods/log 有假阳性，
以直连真实尝试为准：platform-falco/devops 可读、other-ds/aliyun/secrets/petclinic logs 全 Forbidden）。

## 2. 建身份（devops，照 Kyverno/Kubescape/SOPS 先例）

- 用户：`groupadd -g 1007 security-falco; useradd -u 1007 -g 1007 -d /var/lib/security-falco -s /bin/sh -M security-falco`（1002 kyverno / 1003 sonar / 1004 zap / 1005 kubescape / 1006 sops 已占用，1007 为核对 /etc/passwd 后的未占用值）。
- 入口：`/var/lib/security-falco/entry.py`（root 0444，本目录 entry.py 为安装原件）、
  `entry-projects.json`（root 0444，钉死项目/命名空间/标签/kubectl SHA-256）。
- SSH：zhang 侧专用密钥 `~/.ssh/security-manager-v2-falco`（ed25519，0600，
  指纹 SHA256:96HFAZj7hTm8nH0BzN9aVxFXWTfAklgdhyZD2SVUpag）；
  `/var/lib/security-falco/.ssh/authorized_keys`（security-falco 0600）单行
  `restrict,command="/usr/bin/setpriv --no-new-privs /usr/bin/python3 /var/lib/security-falco/entry.py" <pub>`。
  回环主机密钥经 keyscan 与 /etc/ssh 主机密钥指纹三方核对一致
  （SHA256:nKfNkeCTSMNscgQKxptFwg14rsFjTYIWIjSfJ1hwG7s）后写入 zhang known_hosts。
- 集群：`kubectl apply -f rbac.yaml`（本目录原件）；SA 令牌经
  kubernetes.io/service-account-token Secret 生成，组装为
  `/var/lib/security-falco/kubeconfig.yaml`（security-falco 0600；令牌值不落任何文件/日志/证据）。
- 入口校验：SSH_ORIGINAL_COMMAND 必须全匹配 `collect-v1 <projectId> <13位windowEndMs>`、
  uid/gid 与 NoNewPrivs=1 复验、admin kubeconfig 与 docker.sock 不可读复验、
  kubectl 摘要复验、kubeconfig 属主/权限复验、窗口 ±1h、单执行 flock。

## 3. 代码切换

- `falco/collector.mjs`：删除 sudo kubectl 路径；唯一动作是以上述密钥 SSH 到
  security-falco@127.0.0.1 发 `collect-v1 <projectId> <windowEndMs>`，收包后逐字段
  校验（kind/project/window/身份 uid/gid/SA/各结果 status）再成形为原观察形状。
- `falco/projects.json`：新增 collectorEntryUser/Host/Uid/Gid/ProjectId/ServiceAccount(Namespace) 钉死字段。
- `falco-real.mjs`：采集后复验身份字段；runtimeFacts.identity 改为如实标注
  collectorUser/Uid/Gid + SA + dedicatedRestrictedUid=true（runnerUid/Gid 另列，即驱动进程 zhang）。
- `falco-real.test.mjs`：新增 4 测（配置钉死、packet 接受、错身份拒绝、错窗口/项目拒绝），共 8/8。

## 4. 真实复验（devops 执行副本 ~/falco-gf2-work）

```
# 执行副本：Mac 工作区 infra/ 整树 scp 至 devops ~/falco-gf2-work/repo/infra，根写 .git-sha
bash trigger.sh falco-gf2-pos-1            # devsecops-test 受控 Pod，两轮 sh+cat /etc/passwd(SUCCESS)+/etc/shadow(EACCES)
node falco-v2-driver.mjs run web-falco-gf2-pos1 falco-gf2-pos-1 <WINDOW_END_MS> ~/falco-gf2-work/runs/pos1
sudo -n kubectl -n devsecops-test delete pod falco-gf2-pos-1
# 空闲 Pod falco-gf2-neg-1 同 YAML 无 exec，等 20s 后同法跑 web-falco-gf2-neg1
node falco-v2-driver.mjs disabled web-falco-gf2-off1 ~/falco-gf2-work/runs/off1
sudo -n kubectl -n devsecops-test get pods   # 应为空
```

期望与实测见 verification.json：正例 COMPLETED/PASS（冻结口径）、detectedEvents 中
sh/cat 目标动作与触发逐条对账、runtimeFacts.identity.dedicatedRestrictedUid=true 且
collectorUid=1007；负例 Shell/sh-cat 事件 0 不误报；Loki 正例 DELIVERED（ACKNOWLEDGED 204）+ 回查 matched=1。

## 5. 回归（Mac 仓库根）

```
node --test infra/security/manager-v2/falco-real.test.mjs
node --test infra/security/manager-v2/*.test.mjs            # manager-v2 全集
node --test infra/security/*.test.mjs infra/observability/*.test.mjs
node --test infra/security/manager-v2/consumers/*.test.mjs  # 基线 114/162、48 败既有夹具类
```

## 边界

- 未动 Falco DaemonSet/规则/传感器配置；未动 petclinic 业务负载（只读采集其 Pod 列表，与旧 collector 同）；
  测试 Pod 仅 devsecops-test 且验后删尽；生产 Manager NOT_ACTIVE；未触发 Jenkins；Harbor 未写；未 push。
- 入口基础设施保留复用：用户 security-falco、SA/RBAC、kubeconfig（0600）、
  zhang 侧专用密钥、/var/lib/security-falco 入口三件套。
