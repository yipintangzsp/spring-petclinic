# security-test 专用 Colima Profile 配置准备（2026-11-02）

**ISOLATED_PROFILE_READINESS = READY**，范围仅为独立配置文件的创建与静态审核。**VM未启动，runtime/server身份与container smoke未验收，不能据此创建kind或执行SOPS compatibility。**

## 1–2：安装版本与多profile依据

当前Colima **0.10.3**，commit `00f6c297e92a82c04a4ab507db0a61435650d7e8`，安装路径 `/opt/homebrew/Cellar/colima/0.10.3/bin/colima`。

本轮直接读取安装版本的help和本机已有完整配置：

- root help：`-p, --profile string`，明确用于multiple instances，默认default。
- start help：`colima start [profile] [flags]`，支持mount none、Kubernetes、SSH config、activation、CPU/memory/disk/root-disk等独立参数。
- 本地README同样声明multiple instances；既有default配置提供当前版本字段结构。
- 对安装binary只读提取Go函数元数据和少量配置函数反汇编，保存ProfileFromName/ConfigDir及mount转换依据；没有执行start或binary注入。

配置使用当前安装版本已有字段，PyYAML读取校验，加上该版本函数语义检查。没有运行VM renderer；未来启动阶段仍须核对生成的Lima配置，而不能把静态审核当成运行时隔离证明。

## 3：default保护结果

原路径：`/Users/zhangsir/.colima/default/colima.yaml`。

修改前后SHA256相同：

```text
6d22b3bab6a1ab61101506683956b523cc323b9b37aa0cb4bd6d981b9f76ca8a
```

default整个文件树、文件metadata及SHA均前后一致；原生成的 `~/.colima/_lima/colima/lima.yaml` SHA一致。SSH config仅计算哈希、不发布内容，前后相同；kube/Docker client配置stat前后相同，未读取其凭据内容。Docker contexts完整列表和current context前后相同，current仍为 **default**。

没有编辑default、现有SSH/kubeconfig、现有Docker contexts或生产代码。保留的原Gate/Policy/Summary/Jenkins文件哈希也全部一致。

## 4–8：新profile及安全开关

专用名称 **security-test**。创建前确认该profile目录与预期 `colima-security-test` VM目录均无冲突；使用exclusive create，不覆盖已有文件。

唯一新增的宿主配置对象：

- `/Users/zhangsir/.colima/security-test/`，0700。
- `/Users/zhangsir/.colima/security-test/colima.yaml`，0600。

配置SHA256：

```text
bf06fbc527e4b7dd50324d060a58c5f29485ddd2c8f918f22f8885aba14b1b25
```

| 要求 | 新配置 |
| --- | --- |
| HOME_MOUNT | **NONE**：`mounts: null` |
| KUBERNETES | **DISABLED**：`kubernetes.enabled: false` |
| SSH_CONFIG_WRITE | **DISABLED**：`sshConfig: false` |
| AUTO_ACTIVATE | **DISABLED**：`autoActivate: false` |
| SSH agent | **DISABLED**：`forwardAgent: false` |
| 自定义环境/脚本 | `env: {}`、`provision: null` |
| 自定义daemon endpoint | 无，`docker: {}` |
| 生产路径、kubeconfig或凭据mount | 无 |

### 为什么不用 mounts: []

原default的 `mounts: []` 会回退到HOME默认共享。安装版本的CLI `mountsFromFlag` 将 `none` 转为nil；`Config.MountsOrDefault` 对nil不增加挂载，只对**非nil但长度0**的slice补默认HOME。

所以专用YAML明确使用 **`mounts: null`**，对应nil，不使用 `[]` 或省略字段猜测行为。证据在 `local-binary-functions.json`；未来若单独授权启动，还应显式保留 `--mount none`，并在允许后续工作前检查实际Lima mounts无HOME/凭据目录。

## 9：Docker context行为

本轮没有调用Colima start，没有注册或激活新的Docker context。现有default/desktop-linux定义和current状态未变。

未来专用runtime预期socket位于 `~/.colima/security-test/docker.sock`；启动可能创建其专用Docker context，但 **autoActivate=false** 不应切换既有current context。届时需实际核对；现在不把预期socket或context称为已存在。后续可显式指定专用Unix endpoint，避免依赖全局default。

## 10：资源预算

只读硬件观察：Apple M1 Pro、10CPU、32GB RAM。sysctl受sandbox限制，硬件值来自过滤后的system_profiler输出，不采集序列号。df观察为约42,000,000KiB可用、91%使用率。

新配置为 **2CPU、2GiB内存、10GiB data disk、20GiB root disk**，未增加default资源。10GiB数据盘来自安装版本README支持的最小示例，rootDisk保留CLI默认20GiB。总30GiB是虚拟容量上限配置，**本轮没有分配VM或磁盘**；启动前必须重新核对实际空间、缓存和镜像需求，不能把配置READY当作后续Kubernetes资源验收。

## 11–13：网络、凭据与静态审计

网络为原生local shared模式，address/hostAddresses/preferredRoute均false，无custom DNS、dnsHosts、proxy env或Docker daemon覆盖，无生产route/host mapping。portForwarder为Colima管理的VM内部SSH转发，不是注入生产SSH key或agent，sshConfig和forwardAgent都关闭。

**shared不代表air gap**，也不证明生产IP不可达。本轮的结论是配置没有生产依赖、凭据或mount；未来smoke应使用container `--network none`，再单独核对live VM/socket/server身份。

静态扫描配置中无 `~`、`/Users/`、`.kube`、`.ssh`、`.aws`、`.config`、`.docker`、credentials或production路径。未生成synthetic key，也未读取生产age key、Secret、registry/Jenkins/Harbor/AWS凭据。

额外检查本地Colima/Lima全局default/override配置候选与template：未发现会覆盖该profile的default.yaml/override.yaml；COLIMA_HOME/COLIMA_PROFILE/LIMA_HOME均未设置。未修改这些目录的现有内容。

静态审核全部PASS：HOME_MOUNT=NONE、Kubernetes/SSH_CONFIG_WRITE/AUTO_ACTIVATE=DISABLED、REMOTE_DOCKER_ENDPOINT/PRODUCTION_KUBECONFIG/PRODUCTION_CREDENTIAL_MOUNT=NONE。

## 14：回滚边界（仅设计，未删除）

当前profile从未启动。若未来决定撤销这次准备，先核对profile绝对路径、owner、配置SHA以及确无VM/socket/context，再只移除这一份配置文件和空的security-test目录；不使用宽泛目录匹配或全局prune。

如果另一期已经启动，则须先记录并核对专用VM/disk/network/context IDs，再在单独授权范围内使用当前CLI的 `--profile security-test` stop/delete；不得使用无profile/default删除，不得删shared assets、existing contexts、SSH/kube配置、生产项目或K3s平台。本轮没有执行任何删除。

## 15–20：文件、最终结果与停止

宿主仅新增专用目录与配置；repo新增配置副本、审核证据和本文档。**既有文件修改0，default unchanged=YES。** 现有敏感配置内容未输出，VM目录不存在，Kubernetes/API/Secret访问、VM启动、container/kind创建、SOPS执行均为0。

**ISOLATED_PROFILE_READINESS = READY**，无剩余静态配置阻塞。不等于LOCAL_RUNTIME_READINESS或SOPS_ISOLATED_EXECUTION_READINESS已经READY；这些旧结论未修改。

下一允许阶段仅是单独限定范围的 **security-test启动前复核 → 专用runtime启动 → live local VM/socket/Docker server identity → 无网络disposable smoke**。需重查配置/default哈希、空间、镜像获取范围和生成Lima mounts，并保留no mounts/Kubernetes=false/sshConfig=false/autoActivate=false。不能启动default或自动创建kind/SOPS夹具。

本轮到此停止，**没有执行colima start**。

证据目录：`evidence/2026-11-02/isolated-colima-profile/`，包含CLI/binary本地依据、profile布局、static-audit、creation-receipt、protection-before/after、network/rollback、readiness及哈希索引。
