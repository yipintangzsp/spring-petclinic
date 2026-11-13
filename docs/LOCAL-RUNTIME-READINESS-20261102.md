# 本地容器 Runtime 恢复安全检查（2026-11-02）

**LOCAL_RUNTIME_READINESS = NOT_READY**。

本轮按优先级检查了现有Colima和Docker配置。发现现有profile会向VM共享整个可写HOME，不能满足“不得暴露生产kubeconfig”的启动条件，因此遵从用户STEP2的停止规则：**未执行colima start、未修改profile或SSH、未运行container smoke**。没有删除/重建VM，也没有安装其他runtime。

## 1–3：检测结果、候选runtime和profile身份

| 项目 | 本轮证据 |
| --- | --- |
| Colima | `/opt/homebrew/bin/colima`，version0.10.3，commit `00f6c297e92a82c04a4ab507db0a61435650d7e8` |
| Colima status | 10秒有界检查超时，不能据此认定运行或停止 |
| 现有profile | `~/.colima/default/colima.yaml`，没有新建profile |
| 生成VM配置 | `~/.colima/_lima/colima/lima.yaml`，name colima、VZ、aarch64、2CPU、2GiB，Docker runtime |
| 磁盘 | 原配置data100GiB、root20GiB；未扩容、格式化或删除 |
| 网络配置 | shared，未设置reachable address；agent forwarding=false；未改网络 |
| Kubernetes | profile明确enabled=false；未启用integration，也未创建cluster |
| Docker-compatible入口 | default / desktop-linux配置均为local Unix socket，但均不可达；没有已证明可用的替代server |
| 进程检查 | `ps -axo pid=,comm=`被sandbox以EPERM拒绝；未提权重试，不据此断言进程不存在 |

选定审查的候选是**既有Colima default**，不是已恢复成功的runtime。profile元数据表明它配置为本地VM，不足以证明当前运行server身份或安全可复用性；既有disk内容也未被当成可随意丢弃的数据。

## 4–7：context、endpoint与生产依赖检查

当前Docker context保持 `default`：

| context | endpoint |
| --- | --- |
| default | `unix:///var/run/docker.sock` |
| desktop-linux | `unix:///Users/zhangsir/.docker/run/docker.sock` |

`/var/run/docker.sock`是指向不存在的用户socket的symlink。`~/.colima/default/docker.sock`和`~/.colima/docker.sock`也不存在。显式指定local Unix endpoint的docker info返回exit1/ENOENT，server ID/name/version/architecture未取得。其JSON中的空字段和零计数是失败占位，**不是空server、无镜像或无容器的证明**。

生成Lima配置将guest `/var/run/docker.sock`映射到上述本地Colima socket路径；已检查Docker context definitions中没有remote TCP/SSH endpoint。没有连接remote Docker host。但缺少运行中的VM/server/socket证据，不能仅因配置是local而宣布身份验证完成。

关键阻塞是生成配置的实际挂载：

```yaml
mounts:
    - location: "~"
      writable: true
```

profile里的 `mounts: []`并非“没有挂载”；其默认行为在生成Lima配置中实际展开为HOME共享。该共享覆盖生产kubeconfig及其他凭据所在目录。未读取这些凭据内容，但按原配置启动会暴露它们，故不能证明无生产依赖。

此外profile为 `sshConfig: true`、`autoActivate: true`。按默认配置启动可能写入宿主SSH配置并切换当前Docker context；本轮没有自行启用这些副作用。原forwardAgent=false、Kubernetes=false仍不能抵消HOME共享风险。

## 8–9：启动与smoke结果

- runtime start：**NOT_ATTEMPTED**，由profile安全条件不满足触发停止。
- container create/run/remove：均 **NOT_TESTED**，没有安全运行底座就不执行smoke。
- image pull、容器创建、端口映射、mount和network操作：均0。

本轮只读取了 `colima start --help`，没有运行start。当前CLI确认支持 `--mount none`、`--ssh-config=false`、`--activate=false`、`--kubernetes=false`，但这些选项均未应用。它们是后续可单独审查的最小安全调整方向，不是已完成的修复或当前profile的有效配置。

未来只有runtime/socket/VM/server身份均被证明后，才可以使用已批准的本地image digest/image ID，禁止pull、无host mounts、无凭据、`network none`、无ports和受限权限，验证create/start/exit/remove。当前没有为smoke猜测镜像或从网络拉取hello-world/busybox。

## 10–12：文件变更和访问计数

本轮没有主动改写 `~/.colima`、`~/.ssh`、`~/.docker`、`~/.kube`或宿主网络配置。profile/Lima、Gate/runtime/Policy/Summary等所选文件在报告生成前后校验SHA；SSH/kube/Docker client配置仅记录stat元数据，不读取内容。repo中仅新增本轮证据和本文档，未改生产实现或既有验收记录。

| 操作 | 数量 |
| --- | ---: |
| kubectl命令 / Kubernetes API / 生产API | 0 / 0 / 0 |
| 生产凭据、Secret、age private key内容读取 | 0 |
| profile/SSH/全局Docker context主动改写 | 0 |
| runtime start / install / VM删除或重建 | 0 / 0 / 0 |
| smoke容器 / kind cluster / SOPS fixture | 0 / 0 / 0 |
| SOPS/age下载或执行 | 0 |
| Gate / Summary / release / rollout变更 | 0 |

进程查看被sandbox拒绝；本轮未提权或绕过限制，也未据此断言进程不存在。HOME挂载是另有配置证据的独立阻塞。

## 13：SOPS/age ephemeral工具策略（仅设计）

后续优先使用经过身份核验的本地runtime内的临时Linux/arm64 container，不向macOS安装工具。

版本与校验源是已有仓库 `infra/security/scanner-tools.json`，先核对其完整SHA与 `infra/security/tools-lock.json` 的 `supplyChain.scanner_manifest_sha256`，再核对binary bytes：

| 工具 | 锁定版本 | SHA256 |
| --- | --- | --- |
| SOPS | 3.13.3 | `53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77` |
| age | 1.3.2 | `41b072352f4561018949623c674d16ef704019b9108a9bbdbd21292efebfc94f` |
| age-keygen | 1.3.2 | `00b549cebf68302893fc489830f37e706712689ca877f84d85439d700d2997c7` |

工具来源只能是已有受信任本地缓存或另行授权的已验证artifact；本轮没有GitHub/registry下载，也未确认可用image。未来container image须固定可核验的linux/arm64 OCI digest，当前digest未知，不伪造、不使用latest。

新的synthetic age identity仅在未来fixture阶段生成，放入owned tmpfs/temporary storage、mode0600，只读注入明确路径，由BUSINESS_AGE_FILE传至SOPS_AGE_KEY_FILE；不挂载生产key、HOME、kubeconfig、SSH agent、cloud credentials或Docker socket。独立加解密工具container可network none；环境清理所有真实凭据和外部KMS依赖。

完成后移除工具container及专用tmpfs/临时key和synthetic输出，只保留脱敏metadata/hash。上述均为设计，本轮没有key生成、fixture或工具执行。

## 14–16：结论、blocker及下一步

最终 **NOT_READY**，不能推进test cluster创建。

1. **R1：有效HOME可写共享。** 违反启动前不得暴露生产kubeconfig的条件，不能按当前profile启动。
2. **R2：自动SSH/context副作用。** 现有sshConfig/autoActivate均true；没有在本轮自行改profile绕过停止条件。
3. **R3：运行身份和smoke未取得。** status超时、socket缺失、docker info失败，VM/server ID和architecture未知，smoke未执行。

本轮触发用户STEP2的STOP条件，故未继续start。后续若单独授权最小安全调整，可仅对该既有profile收窄/移除HOME共享、避免自动SSH/context写入，保留Kubernetes disabled及原VM/data/network；再核对生成配置，重新决定是否启动和进行无网络smoke。不得大规模重建、删除VM、改宿主关键网络或生产配置。

READY条件未成立，因此本轮没有“已允许创建kind”的下一步。到此停止，不创建Kubernetes测试集群、不运行SOPS compatibility、不进入Summary。

证据目录：`evidence/2026-11-02/local-runtime-recovery/`，含inventory、profile-assessment、identity-proof、start-decision、smoke-result、tool-strategy、readiness及完整性记录。
