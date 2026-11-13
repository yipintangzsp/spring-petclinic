# security-test 本地隔离 Runtime 启动与 Smoke 验收（2026-11-02）

**LOCAL_ISOLATED_RUNTIME = READY**，范围仅为专用runtime启动、真实VM/socket/server身份、凭据/挂载隔离，以及无网络container create/run/remove。**不代表guest互联网DNS、Kubernetes测试集群或SOPS执行环境已就绪。**

专用runtime保持运行。本轮没有创建kind/其他Kubernetes集群、调用现有Kubernetes API、执行SOPS/age、创建fixture、改Gate/Summary或rollout。

## 1–2：启动前保护与启动结果

启动前重新核对批准配置及保护对象：

| 对象 | 启动前后结果 |
| --- | --- |
| default配置 | SHA256不变：`6d22b3bab6a1ab61101506683956b523cc323b9b37aa0cb4bd6d981b9f76ca8a` |
| security-test批准配置 | SHA256不变：`bf06fbc527e4b7dd50324d060a58c5f29485ddd2c8f918f22f8885aba14b1b25` |
| 原default Lima配置 | 哈希不变 |
| 用户 `~/.ssh/config` | 哈希不变 |
| 用户 `~/.kube/config` | 哈希不变；只计算哈希，未解析或输出内容 |
| 用户 `~/.docker/config.json` | 哈希不变 |
| 生产项目/此前证据 | **3243份既有文件SHA全部不变** |
| 全局Docker current context | 始终default |

仅执行了下列专用启动命令，未启动default：

```text
colima start -p security-test --mount none --kubernetes=false
  --ssh-config=false --activate=false --save-config=false
```

启动子进程只接收HOME/PATH等必要宿主环境变量名，没有传入KUBECONFIG、AWS、SOPS、age、Jenkins、Harbor或SSH agent凭据变量。没有修改批准profile来满足启动。

结果exit0，UTC **01:04:18.823 → 01:06:57.811**（本地09:04:18→09:06:57），耗时 **158.988秒**。首次启动下载了Colima基础磁盘镜像并生成专用VM状态；日志完整保留，没有改宿主DNS或registry。

## 3–6：VM、Docker与endpoint身份链

| 字段 | 实际证据 |
| --- | --- |
| Colima profile | security-test |
| Lima instance | colima-security-test |
| instance目录 | `~/.colima/_lima/colima-security-test` |
| VM实现 / Lima版本 | VZ / 2.2.0 |
| VM hostname | security-test |
| VM machine-id | `a093ffaa4d594b5298d97235be9e69ae` |
| VM系统 | Ubuntu24.04.4 LTS，Linux6.8.0-117-generic |
| VM/Docker架构 | aarch64；smoke image为linux/arm64/v8 |
| Docker server name | security-test |
| Docker server ID | `f0a9c4bb-ef14-4087-b0b1-7d5f02aa1ff8` |
| Docker version | 29.5.2 |
| Docker root dir | /var/lib/docker，映射至VM自己的data disk |
| local guest IP | 192.168.5.1/24 |
| endpoint | `unix:///Users/zhangsir/.colima/security-test/docker.sock` |
| socket权限 | 当前用户所有、0600、真实Unix socket |
| remote Docker TCP/SSH endpoint | NONE |

证明不依赖context名称：原批准配置 → 新实例目录/VZ标识 → guest hostname/machine-id/kernel/arch → Lima guest Docker socket映射 → exact host socket → Docker server name/kernel/arch/稳定ID。所有Docker操作显式指定该socket，没有依赖全局default。

Colima为专用profile注册了 `colima-security-test` context，但**未激活**；此前default、desktop-linux定义与current状态均未变。

## 7–8：实际mount与凭据检查

生成的Lima配置实际为 `mounts: null`、`loadDotSSHPubKeys:false`、`forwardAgent:false`；生成的完整profile也保持Kubernetes=false、sshConfig=false、autoActivate=false。

VM内真实findmnt未见HOME、/Users、生产checkout、.kube/.ssh/.aws/.docker等宿主挂载。只有VM自身root/data disks、系统pseudo filesystems和Lima启动ISO；例如 `/mnt/lima-colima-security-test` 及绑定的Docker/containerd目录属于专用VM内部磁盘，不是宿主生产目录。

用户及root下的kubeconfig、AWS配置/credentials、Docker auth config、SOPS/age key标准路径、用户SSH config，以及 `/Users` 和k3s kubeconfig路径均ABSENT。只检查exists/path，不读取文件值。login与dockerd环境只记录变量名；未发现KUBECONFIG、AWS、SOPS/AGE、BUSINESS_AGE、Jenkins、Harbor、DOCKER_AUTH_CONFIG或SSH_AUTH_SOCK。

**观察到guest登录环境有HTTP_PROXY/HTTPS_PROXY及小写对应变量名**，如实保留；其值未读取。dockerd环境未见proxy变量名。smoke使用全新空Docker client config，image环境只有PATH，未注入proxy或凭据，且network none。本轮不把“配置未注入生产依赖”扩大成VM网络air gap证明。

VM管理SSH使用Colima自己的本地管理通道；未加载用户SSH公钥、未转发agent、未读取生产SSH或age私钥。与启动时生成的Lima管理密钥/SSH状态不能混同为生产凭据。

## 9–11：全局context、SSH及kubeconfig

启动后、smoke后均核对：

- Docker current仍为 **default**，DOCKER_HOST未设置；旧context记录完全一致。
- 用户SSH config SHA相同，未编辑 `~/.ssh/config`。
- kubeconfig SHA相同，未调用kubectl，也未解析其内容。
- 专用profile和default配置SHA相同。

Colima自己管理的 `~/.colima/ssh_config`、Lima用户网络metadata等被启动过程生成/更新时间；它们列入host artifact记录，不谎称宿主零文件变化。这里的SSH保护结论明确指用户 `~/.ssh/config`，不是把runtime内部管理文件说成未生成。

## 12：smoke镜像与公共下载事实

全新runtime的本地image/container/volume列表为空，只有bridge/host/none默认network。

普通公共源是 **docker.io/library/busybox:1.37.0**，没有登录私有registry或使用Harbor。首次daemon直接pull失败：registry-1.docker.io向 `[::1]:53` 查询，连接被拒绝。

保持DNS配置不变，使用宿主已安装skopeo，以显式匿名、TLS验证、linux/arm64选择从同一公共源复制到临时archive，再通过专用socket `docker load`。来源仍是普通公共镜像；没有新安装工具，没有采用私有镜像或绕过TLS。临时archive约4.35MB，使用后删除。

实际运行固定本地image ID：

```text
sha256:a857f5e40d4beae99279dfecb7124b92b4f32a85c980f92cd6b2fe747e9d4b86
```

下载的config digest与Docker当前containerd store的image ID是不同类型；初版将两者直接比较，检查在创建容器前停止。随后使用只读image export校对config bytes SHA，确认与下载config完全相同，再使用固定本地ID运行。没有关闭身份检查；两个digest及绑定证明保留。

## 13–15：唯一容器、结果和清理

只创建了一个owned smoke容器：

```text
security-test-runtime-smoke-20261102011227
```

实际命令：

```sh
/bin/sh -c 'printf "%s\n" SECURITY_TEST_SMOKE_OK'
```

创建时强制pull never、**network none**、无mount/volume/socket/port、非privileged、read-only root、cap-drop ALL、no-new-privileges、UID/GID65534、pids16、memory32MiB、CPU0.25。启动前inspect逐项验证；container Env只有image原PATH，没有host凭据或proxy继承。

结果：输出 **SECURITY_TEST_SMOKE_OK**，实际container exit0、OOMKilled=false。随后普通rm exit0，inspect返回no such object，全量post-list再次确认为空。没有重新运行第二个smoke容器。

最初清理核对对“no such”大小写作了错误假设；已以实际小写错误、rm结果和空container列表完成独立复核，原trace保留，不伪造退出或删除结果。

post-smoke：container0、volume0、network IDs与runtime默认baseline完全相同。临时公共archive、只读image-export archive、空auth文件和宿主skopeo公开blob metadata缓存/临时client目录均已按owned路径清理；未生成或保留任何凭据材料。公共BusyBox镜像留在专用runtime缓存中，runtime按要求继续运行。

## 16–19：后验保护、访问计数与文件变化

全部保护哈希再次一致，包括default、批准profile、SSH、kubeconfig、宿主Docker config和3243份既有项目文件。具体前后SHA见 `pre-start-protection.json`、`post-protection.json`。

生产API访问 **0**；kubectl/Kubernetes API **0**；生产Secret/age私钥/凭据值读取 **0**。SSH/kubeconfig仅按要求做hash-only，不解析、显示或复制其内容。真实SOPS/age、kind/k3d/k3s、fixture和rollout均0。

宿主变化是本次批准启动所需的Colima管理产物：

- 新 `security-test` socket、`_store/colima-security-test.json`。
- 新Lima instance目录、root/data磁盘、启动ISO、VZ状态和管理日志。
- Colima基础磁盘镜像cache、专用Docker context metadata。
- Colima管理的SSH/network metadata及用户态network daemon状态。
- 本轮repo证据和本文档。

这些按metadata保留记录，部分shared管理文件没有启动前完整byte快照，因此不声称对全部管理文件做了精确before/after diff。**受保护的用户/生产配置与项目文件明确不变。** 未手工修改宿主关键网络、DNS、生产route、default profile或global current context。

## 20–22：READY边界、剩余限制与下一步

本轮所有指定runtime-only READY条件均成立，最终：

**LOCAL_ISOLATED_RUNTIME = READY**。

但guest在线拉取存在明确未修复问题：只读检查发现 `/etc/resolv.conf` 不存在，未观察到UDP53 listener；daemon直接公共pull因此失败。该诊断shell的最后ss/awk返回0，不代表前面的cat成功；缺文件错误原样保留。**尚未确定为何启动后缺失resolver文件，也未宣布永久修复。**

本次通过宿主匿名公共image copy/load完成无网络smoke，符合runtime create/run/remove验收；不能据此宣称guest在线pull、Kubernetes或SOPS环境READY。guest代理变量值也未审查，只记录其名称存在；未转入smoke。

下一允许阶段应单独限定为 **security-test guest DNS只读诊断及最小修复/公共image可用性复核**，再复核disposable Kubernetes与工具环境设计。不得因此改宿主/生产DNS，不自动创建kind、namespace或SOPS fixture。

本轮到此停止；专用runtime保持运行，未进入Summary、Gate或其他结构性工作。

证据目录：`evidence/2026-11-02/isolated-runtime-start/`，含start、rendered-Lima、VM/server identity、mount/env-name检查、公开image acquisition/binding、smoke、post-resource/protection、DNS限制、cleanup、readiness及完整性索引。
