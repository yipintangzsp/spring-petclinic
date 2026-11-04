# Trivy validation guard boundary closeout — 2026-11-04

本轮完成路径维护边界修复、禁止不安全进程启动、版本化兼容性回归及独立恢复收据。真实 validation 执行仍 NOT_READY；没有刷新 DB、扫描、Dojo、发布、rollout 或 push。

## 修复范围与前后证据

- 旧 Guard 使用 process group，脱离 session 的后代可逃逸；metadata symlink 可越界；调用方声明的 storage domain 不能证明实际写入边界。原样回放 `legacy-guard/tests.log`（80/80）及 `legacy-guard-linux.log` 保留旧实现的失败行为复现，不能解读为旧实现安全。
- 新实现不伪装为完成内核隔离：所有 validation command 在 spawn 前返回 NOT_READY / commandStarted=false；不返回虚假 descendantsStopped=true。残留或 cleanup 不确定时拒绝后续操作，不使用广域 kill。
- 描述符相对 open/unlink/rmdir，逐层 O_NOFOLLOW；UID/0700、设备/inode/nonce、独占 owner 文件、六个子目录身份、metadata regular-file/nlink/FIFO 检查；目录替换竞态和 traversal 负例均通过。root 必须是 OS 临时根下专用私有父目录，禁止 HOME/root/可变 TMPDIR 授权。
- cleanup 仅针对确认归属的 fixture 目录，不跟随 symlink。Linux /proc/self/mountinfo 拒绝嵌套 mount（含同设备 bind）；bind 场景通过注入 mountinfo 测试，没有创建实际 mount。
- Guard 自行采集 cache/tmp/report/evidence/logs/manifests 的真实设备、容量、可用字节和 inode；调用方 sampler 明确 observationOnly，不能授权 execution。未知物理 backing、Docker/runtime、COW、外部 writer 或峰值上界仍阻塞。
- boundedSample 补同步阻塞后的 elapsed 检查；超时、指标失败、未知峰值/瞬时写入/清理空间均不能转为 READY。没有执行高速写盘或真实 scanner，不能宣称运行监控/终止延迟已经验证。

## 跨平台支持边界

- Darwin ARM64：描述符路径维护已验证；当前代理沙箱不能发现用户临时根时 fail closed，最终 fixtures 显式使用固定 /tmp。无已验证 scanner sandbox，mount identity 不完整。
- Linux ARM64 UID1000：同样验证路径维护；普通用户 session cgroup 和 cgroup.kill 不可写，bwrap 缺失。没有创建 cgroup、挂载、namespace 或扩大权限。进程/后代隔离和任意 scanner 写入约束尚未实现。
- PATH_BOUNDARY/SYMLINK 的 VERIFIED 只适用于私有 fixture 的 Guard 文件维护 API；不代表任意原生程序被文件系统沙箱隔离，也不覆盖同 UID 恶意并发者。所有 scanner launch 仍被拒绝。

## 生产兼容性

- 默认 production，显式 validation/validation-only 单次配置；ambient TRIVY_GUARD_MODE 不改变 production 分支。release/promotion/rollout 请求拒绝。
- scanner-db-refresh.mjs 与生产调用方字节未变。生产公式 capacity×15%+12GiB、validation hard floor ceil(capacity×15%+8GiB)、采样与退出阈值未变。
- 旧/新版 Trivy 各 190/190，184 个 frozen differential 样本完全一致，rawPreserved=true，三份新生成 aggregate 在两版本间 byte-identical。仅证明冻结 production logic，未运行 Trivy。

## 历史证据

- ORIGINAL_EVIDENCE_INTEGRITY=FAILED。三份旧 aggregate 的期望/实际 hash 及新重放 hash 详见 evidence-recovery-receipt-v2.json。没有替换原文件或重写原 manifest。
- 新独立收据可用于明确版本的 controlled replay 兼容证明，不能修复历史链连续性，不能描述为历史生产事故、same-run 16/16 或 runtime 完成。
- 824 个保护文件在本轮开始/结束 SHA256 一致；冻结测试仅写新克隆树。Node 写拦截是防意外覆盖机制，不是恶意程序安全沙箱。

## 最终实际测试

| Suite | Platform | PASS | FAIL | SKIP |
|---|---|---:|---:|---:|
| original-v1 | macOS-27.2-arm64-arm-64bit-Mach-O | 190 | 0 | 0 |
| helm-versioned | macOS-27.2-arm64-arm-64bit-Mach-O | 190 | 0 | 0 |
| legacy-guard | macOS-27.2-arm64-arm-64bit-Mach-O | 80 | 0 | 0 |
| source-lock | macOS-27.2-arm64-arm-64bit-Mach-O | 54 | 0 | 0 |
| helm-shadow | macOS-27.2-arm64-arm-64bit-Mach-O | 43 | 0 | 0 |
| runtime | macOS-27.2-arm64-arm-64bit-Mach-O | 143 | 0 | 0 |
| regression | macOS-27.2-arm64-arm-64bit-Mach-O | 147 | 0 | 0 |
| policy-core | macOS-27.2-arm64-arm-64bit-Mach-O | 5 | 0 | 0 |
| contract | macOS-27.2-arm64-arm-64bit-Mach-O | 10 | 0 | 0 |
| guard-darwin | macOS-27.2-arm64-arm-64bit-Mach-O | 106 | 0 | 4 |
| path-races-darwin | macOS-27.2-arm64-arm-64bit-Mach-O | 9 | 0 | 0 |
| evidence-protection-darwin | macOS-27.2-arm64-arm-64bit-Mach-O | 15 | 0 | 0 |
| guard-linux | Linux-7.0.0-38-generic-aarch64-with-glibc2.39 | 106 | 0 | 4 |
| path-races-linux | Linux-7.0.0-38-generic-aarch64-with-glibc2.39 | 9 | 0 | 0 |
| evidence-protection-linux | Linux-7.0.0-38-generic-aarch64-with-glibc2.39 | 15 | 0 | 0 |
| legacy-guard-linux | Linux-7.0.0-38-generic-aarch64-with-glibc2.39 | 80 | 0 | 0 |

每项实际命令、平台、退出状态见 test-matrix-final.json 与对应 execution.json。不同 suite 有重叠，不合并冒充唯一能力数量。两平台各 4 项 kernel 生命周期测试未执行，不算 PASS。

## 中间失败与清理

- 保留所有 attempt 日志：首次 fixture 目录权限不正确；Helm clone 缺缓存；runtime clone 缺固定依赖/写入拦截 FD 支持。这些已修正 harness 并按完整入口重跑，最终矩阵均 exit=0。旧 subset 123/108 不替代最终 Runtime143/Regression147。
- native temp-root 强化后，默认用户 T 目录在代理沙箱内无法认证，旧轮 fail closed；一个测试辅助 interval child 因 fixture 在 try/finally 前失败而残留。已按 UID、精确命令及测试父进程核验后定向 SIGTERM，未操作生产进程（failed-harness-child-cleanup.json）。修复为先创建 fixture 再启动 child；新一轮两平台通过。空的失败 fixture 父目录仅用 rmdir 清理，见独立 receipt。
- Linux 四轮传输均为用户已批准的 11 文件范围；严格 host-key 校验、普通用户、无 Secret。最终临时树清理完成，linux-execution.json retainedPath=null；先前输出按 attempt 保存。

## 生产只读核验

- Jenkins #270 SUCCESS；V1 Summary hash ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8。
- Argo CD Synced/Healthy，三节点 Ready，PetClinic 3/3、3 ready Endpoint、HTTP200；Deployment/Service/Ingress/Application spec、镜像 digest 与既有基线一致。核验时间详见各 JSON，不将一次取样当作持续 SLA。
- 生产镜像 sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137；Trivy STS/PVC/DB 元数据与文件大小/mtime 未变，DB 未刷新。
- guest available 约42.48GiB，hard floor约45.78GiB；两份 DB 仍过期，完整性和刷新峰值未完全证明。

## 未解决问题与允许的下一步

需另行取得或设计可验证的最小权限进程/文件系统隔离运行环境，验证正常退出、多级 daemon 后代、SIGTERM/SIGKILL、取消和残留清理；同时证明全写入域、物理 backing、刷新/扫描峰值、瞬时写入和失败清理预算。当前环境无法安全实现的能力如实保持 INCOMPLETE。本轮停止，不触发任何下一阶段或资源权限变更。

## Verdicts

```text
TRIVY_GUARD_PROCESS_ISOLATION = INCOMPLETE
TRIVY_GUARD_DESCENDANT_CLEANUP = INCOMPLETE
TRIVY_GUARD_PATH_BOUNDARY = VERIFIED
TRIVY_GUARD_SYMLINK_PROTECTION = VERIFIED
TRIVY_GUARD_STORAGE_DOMAIN = INCOMPLETE
TRIVY_GUARD_RUNTIME_MONITOR = INCOMPLETE
TRIVY_GUARD_PRODUCTION_COMPATIBILITY = VERIFIED
TRIVY_VERSIONED_COMPATIBILITY = VERIFIED
ORIGINAL_EVIDENCE_INTEGRITY = FAILED
EVIDENCE_RECOVERY_RECEIPT = VERIFIED
TRIVY_VALIDATION_EXECUTION_READINESS = NOT_READY
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
FINAL_WIRED_CAPABILITY = 14/16
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
RELEASE_COUNT = 0
ROLLOUT_COUNT = 0
```

提交仅包含本轮十个源码/测试文件和独立新证据；现有其他 dirty/untracked 文件保持原状。该工作树包含此前尚未跟踪的架构依赖，本轮提交不能单独视为可部署发布包。未 push。
