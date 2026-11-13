# Traceable Linux Node executor — 2026-11-02

```text
NODE_EXECUTOR_READY
```

本轮仅补 Node 执行环境。生产 Gate/Policy 没有执行，SOPS_COMPATIBILITY 保持上一轮 INCOMPLETE。用户明确批准：本轮只验 Node 与 guard 的 synthetic profile 单元集成，不重建已清理的真实SA/token。

## 19 项结果

| # | 要求 | 证据 / 实际结果 |
| --- | --- | --- |
| 1 | frozen Gate Node requirement | 没有 Gate-specific engines、exact version、package.json 或 lockfile。入口 node infra/security/secrets-gate.mjs；.mjs ESM、top-level await、node: 内置模块；工作目录为仓库根，读取 scanner-tools/tools-lock 与后续 .git-sha/密文。未把其他 relay 的 Node24.18.0 当本 Gate 版本约束。 |
| 2 | selected Node version | 22.23.3，明确选择的可追踪测试 pin，实际加载确认兼容；不是臆造的生产精确版本，也不宣称穷举验证了所有更低版本。 |
| 3 | source / image | 官方 https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-arm64.tar.xz；复用现有基础镜像 sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f，无新镜像 pull/build。 |
| 4 | digest / SHA | archive SHA256 a44aeb94849a299b22df10b9e622ec2f605c2183501bc40590705131de7c740f，匹配同版本官方 SHASUMS256.txt。实际 node executable SHA256 d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d；runtime 1967文件摘要留档。 |
| 5 | architecture | 实际 uname Linux/aarch64，Node process.platform=linux、process.arch=arm64；二进制 ELF64 e_machine=183/AArch64。 |
| 6 | executor form | security-test 专用 Docker endpoint，一次性非root UID65532容器；只读 rootfs、drop ALL、no-new-privileges、512Mi/1CPU/64PIDs、network=none、tmpfs工作区；stdin传无凭据工具/源码，不挂host HOME/production kubeconfig/keys/socket。Node测试工具存于 /private/tmp/sm-node-executor-erg_cakg，无全局安装。 |
| 7 | dependency model | 仅Node内置模块。无需 npm install/npm ci/vendored project node_modules；未接入任何package registry。官方runtime自带npm仅验证版本10.9.9，不作为Gate依赖。 |
| 8 | lockfile / package evidence | 直接 import closure 无 package manifest/lockfile；未创建或改 repository lockfile。Node tarball+runtime hash、冻结四个源文件 hash 和相对路径记录于 gate-node-requirements.json/runtime-files-sha256.json。 |
| 9 | guard integration | 同一 isolated_sops_executor.py / MIN_RBAC_EXECUTOR；实际Node子进程继承guard sanitized env、clean HOME、private snapshot；5/5 sanity。按用户明确确认，live verify transport 此轮采用synthetic profile单元集成，未向API发假token，不声称真实SA认证通过；无admin fallback。 |
| 10 | Node sentinel | 原生 node -e exit0，v22.23.3、linux/arm64、固定 /fixture/runtime/bin/node、cwd=/fixture/work。 |
| 11 | .mjs startup/import probe | exit0；真实加载6个builtin、真实import未改scanner-runtime且执行原manifest hash检查；未改Gate源码用 SourceTextModule解析并链接，status=linked；不evaluate Gate body。 |
| 12 | previous exit127 eliminated | YES，仅指Node启动阻塞。本轮无MODULE_NOT_FOUND，未以VM/mock gate进行任何决策回放。 |
| 13 | production files modified | NO；3989个既有项目文件全部摘要未变，含Gate/runtime/adapter/Policy/Summary/Manager/guard。 |
| 14 | production API access | 0；本轮 test Kubernetes API 也为0。 |
| 15 | production Secret/key reads | 值提取/解析/使用0；受保护配置只做字节SHA对照，不把hash读取写成从未读取任何配置文件字节。 |
| 16 | resources created | Kubernetes资源0、age key0、fixture0；仅一个临时测试容器，已 --rm 清理；专用现有kind保留。新增文件仅证据目录与私有Node工具scope。 |
| 17 | NODE_EXECUTOR result | NODE_EXECUTOR_READY，限Node/runtime/module启动与本轮获批guard单元集成，不代表SOPS_COMPATIBILITY VERIFIED。 |
| 18 | remaining blocker | Node runtime本身无阻塞。真实min SA认证/容器API transport与实际Gate逐调用事实观察仍属下一阶段前置，未被本轮synthetic transport替代或宣称已闭环。 |
| 19 | fixture rebuild plan | fixture-rebuild-plan.json：新run sm-sops-20261102-02、新UID基线；核对Node工具树，准备官方SOPS/age并校验；两对一次性key；3namespace、获批3SA、5Role/5Binding+1identityClusterRole/Binding；Lease holder使用新run；4synthetic Secret+4ciphertext；27auth检查、短时token/真实SelfSubjectReview/CA/server/nsUID校验；4正向+wrong-key验证，记录完整基线。全部PLAN_ONLY，本轮不创建。 |

## 启动探针边界

冻结 secrets-gate.mjs 没有dry/startup模式，顶层会立即调用requireLease；直接import它会执行本轮禁止的Gate路径。因此探针只：

1. 经原guard创建清洁环境，实际运行node -e无害哨兵。
2. 实际加载node:fs/util/crypto/net/os/child_process。
3. 实际import未修改scanner-runtime.mjs，读取冻结scanner-tools/tools-lock并完成原manifest SHA检查，没有调用requireLease/read/kube/verifyTools/withScanner。
4. 从原始字节构造vm.SourceTextModule，链接到实际加载的依赖namespace，仅用于语法/导出链接检查，不调用evaluate。SyntheticModule只是测试link adapter，不返回虚构API结果、不运行Gate判定。

因此本轮证明runtime、ESM和所需依赖可用，**没有证明完整Gate已经实际执行**。测试参数--experimental-vm-modules只用于无害链接探针，不修改生产命令/语义。来源：[版本对应ESM文档](https://nodejs.org/download/release/v22.23.3/docs/api/esm.html)、[VM module文档](https://nodejs.org/download/release/v22.23.3/docs/api/vm.html)。

## 版本选择与完整性

Gate未声明精确Node版本，不能从没有约束推导出唯一patch。选择官方22.23.3作为此次独立测试版本并固定SHA，再用实际加载验证当前Gate import closure。该选择不是更新生产Node，也不是“最新版本”自动解析。官方来源仅使用同一固定版本目录和 [SHASUMS256.txt](https://nodejs.org/dist/v22.23.3/SHASUMS256.txt)。已完成HTTPS官方SHA匹配和本地ELF/版本验证；未执行GPG签名验证，不宣称独立发布者签名验证完成。

## 持续边界与保留

无fixture、无age key、无Secret、无Lease、无RBAC创建；没有 npm安装、私有registry登录、production mount、生产context切换、rollout或其他组件工作。guard源码未变。临时容器删除，固定基础镜像和kind不改，私有Node运行文件保留在runtime-root.json所指scope，便于后续按hash复用。

后续真实兼容性不能复用本轮mock live-verifier。容器启动验证采用network=none，不能假定容器内127.0.0.1能访问host API；必须在另行批准阶段解决固定API地址、CA/UID、真实min-token验证和同一guard transport。实际Node Gate逐调用观察也需独立验证，不把此前Python观察单元测试当作已实现Node Gate采集。

## 证据

- node-lock.json、SHASUMS256.txt、verified-node.json、runtime-files-sha256.json
- startup-result.json（包含真实Node版本、guard返回、精确env names、ESM链接结果）
- container-execution.json、base-image-identity.txt、runtime-after.txt、context-after.txt
- gate-node-requirements.json、protected-after.json
- fixture-rebuild-plan.json、readiness.json、evidence-index.json、index-validation.json

STOP：本轮不自动重建fixture，不运行Gate/Policy，不接Summary。
