# devops VM 扩容前维护、恢复与扩盘计划（未执行）

本文件只固定未来操作顺序，不是可执行脚本。当前所有写操作被容量与备份门禁阻止。未创建 VM 备份，未验证恢复，未关机，未扩盘。无需重复请求已有条件授权；必须先满足下列客观前提。

## 固定对象与容量

- UTM 4.7.5 / QEMU aarch64，VM devops，UUID `4C8DEDBC-D2FB-43F6-99EC-C2C6F9C1FF46`。
- 原 bundle `/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm`。
- 原磁盘 `/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm/Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2`；唯一可写 VirtIO 磁盘。EFI `Data/efi_vars.fd`，配置 `config.plist` 必须一起保护。
- 虚拟容量 258 GiB，qcow2 宿主逻辑长度约 340.69 GiB，宿主实际占用约 204.98 GiB；三个量不可混淆。后两者会随运行变化。
- 当前备份目标 `NONE`。未来目标必须是经过实测、具备权限隔离的独立存储上的新空目录；不得填造 `/Volumes/...`。
- 当前容量预算详见 `host-capacity-model.json`。全 bundle 保守备份预算约 342.69 GiB（逻辑长度加 2 GiB），另有增长、metadata 1 GiB、临时 4 GiB、macOS 保底 16 GiB。此 reserve 是本轮保守运维预算，不是 Apple 保证值。
- 同一 APFS 稀疏小文件实验只验证工具；不能用它承诺全 VM 的分配量。若未来实测目标支持稀疏/COW，可以有证据地重算预算，不能凭推测减去备份空间。

## 阶段 1：一致备份前提

1. 重新测量目标文件系统可用容量、单文件能力、实际写入/读取和持久性，目标不在 repo、不在当前 bundle、不与生产共享可写目录。确认备份及恢复暂存都容得下；若恢复需另存完整损坏副本，另预算一份，不默认零成本 clone。
2. 记录当前集群、三节点、PetClinic Deployment UID/generation/revision、EndpointSlice、HTTP、Harbor protected digests、Jenkins #270 及 validation #30、源哈希；备份记录不得导出凭据。
3. 再确认所有 Jenkins 构建空闲、runtime validation 空闲、Harbor GC/复制/DB refresh 空闲。API 所见空闲不能证明不存在手动 registry 或 Kubernetes 维护。本轮没有取得独占窗口；未来必须明确维护所有者及暂停新任务的办法，不能把未知当 idle。
4. 维护窗口需要覆盖停机→复制→全量 hash→离线 check→原 VM 启动及健康恢复；时间取决于未来目标实测吞吐，目前不虚报时长。控制平面以及位于该 VM 的 Jenkins/Harbor 会停机，worker/API 通信会受影响，不承诺业务零中断。

## 阶段 2：关机、证明无占用、创建备份

仅在阶段 1 通过后：通过已信任 SSH（`StrictHostKeyChecking=yes`、现有 HostKeyAlias）执行 guest `sudo shutdown -h now`。SSH 中断本身不等于关机成功。

必须逐项证明 UTM 报 Stopped、目标 VM 的 QEMU/QEMULauncher 进程已退出、该 qcow2 无任何打开句柄/写入者。宿主 `lsof '<精确磁盘路径>'` 无输出还需区分“无占用”的正常返回与权限/检查失败；权限不足、输出不可解析、状态旧或未知都终止。仅搜索 `qemu-system` 不够，当前实际写进程名是 QEMULauncher。不得用 `-U`/`--force-share` 跳过写操作锁。

复制完整 bundle：使用本机已验证的 `rsync -aS --extended-attributes SOURCE_BUNDLE/ PRECREATED_EMPTY_BACKUP_BUNDLE/` 目录到目录形式，不使用 `--delete`。目标目录必须事先按阶段 1 验证并精确绑定 VM UUID；禁止覆盖已有备份。记录退出码。工具测试未证明 ACL/owner 等所有外盘属性；若目标不能保留必要属性，停止并选支持的存储/工具，不能宣称备份通过。

对静止源与备份逐文件记录相对路径、大小、模式、配置/EFI 身份、SHA-256，比较文件清单，确保无漏项、截断、重链接到原可写盘；复核备份镜像 virtual-size/format/chain。

只在**离线备份副本**执行 `qemu-img info --output=json '<备份镜像>'` 和 `qemu-img check -f qcow2 '<备份镜像>'`，记录输出和退出码；不用修复参数，不 CHECK 活动原盘。backup exists + static source + release proof + 完整 hash/size/metadata + info/check 全通过才 BACKUP_VALIDATION=VERIFIED。失败时保留诊断，不做 resize。

通过 UTM 启动原 VM，保持原 UUID/EFI/磁盘绑定；验证 rootfs、网络、k3s、节点 Lease、Jenkins/Harbor、PetClinic 和 digests。**原 VM 重启不是备份恢复验证。**

## 阶段 3：恢复方案与验证等级

预定恢复路径是上面精确原 bundle 路径；具体备份来源尚不存在，因此 RESTORE_READINESS=NOT_READY。

实际故障回滚时：停止目标 VM→重新证明无句柄→在空间允许且需要时保存损坏副本及日志→校验备份 hash→将已验证完整备份恢复到精确原路径→再次比较 config/EFI/disk 身份及 hash→在 UTM 打开/附加原身份→启动→检查根盘/ext4/内核错误、网络/DNS/API、k3s/Lease、Jenkins/Harbor、PetClinic endpoints/HTTP 和受保护 digest。不得同时启动同身份副本。恢复需要还原整份盘，不采用缩盘逆操作。

等级区分：METADATA_ONLY 也要求实际存在的备份；OFFLINE_IMAGE_VALIDATED 要实际备份 info/check/hash 通过；ISOLATED_BOOT_VERIFIED 要实际隔离启动及验证。本轮无备份，等级为 NOT_VALIDATED，不能拿活动源 info 冒充备份验证。

若将来测试隔离启动：使用独立恢复目标与新 UUID/MAC，禁用**全部**网络适配器，不仅换子网；禁用共享宿主可写目录/外部生产卷及任何生产写入通道；不能连接 live k3s、数据库、Harbor/Jenkins。启动前证明 CPU/RAM 预算。目前宿主 32 GiB，原 VM 22 GiB + Colima security-test 2 GiB，再起 22 GiB clone 尚未计 OS 就超预算，故不尝试。不得覆盖当前 VM 来测试恢复。保持备份原件只读，测试用副本需要另有容量。

## 阶段 4：离线 backing 扩盘方案（未授权实际执行条件尚不满足）

维护模型 OFFLINE_EXPANSION_REQUIRED。采用停机后的 `qemu-img resize`，不直接编辑 UTM plist 伪造磁盘容量。已识别本机 `/opt/homebrew/bin/qemu-img`；支持的 qcow2 离线增长语义参考 [QEMU qemu-img](https://www.qemu.org/docs/master/tools/qemu-img.html) 与 [UTM resize](https://docs.getutm.app/settings-qemu/drive/resize-and-compress/)。安装版本及最终参数仍要在执行当天复核。

只有 8 个硬门禁全部满足（BACKUP_VALIDATION=VERIFIED，其余 READY），再次捕获健康、暂停验证活动、干净关机、fresh image-in-use guard 通过、最终备份校验通过后，才允许执行唯一选定的增长方案。

当前 selectedExpansionSize=NO_SAFE_EXPANSION_SIZE_CURRENTLY，以下是两个**互斥候选**，均未执行：

- 若未来选择 +16 GiB：`/opt/homebrew/bin/qemu-img resize -f qcow2 '/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm/Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2' +16G`，预期 guest disk 274 GiB。
- 若未来选择 +32 GiB：同一精确命令仅将最后参数换为 `+32G`，预期 290 GiB。

禁止 resize 活动盘、commit/rebase/convert/amend、无锁强写、缩盘。此方案不用 convert 额外复制；若工具要求改格式，停止重新评估容量与权限范围。先 info 核实结果，再启动同一原 VM；失败走验证过的冷备份恢复，不能继续分区操作。

## 阶段 5：guest 分区和 ext4 增长方案

当前 GPT `/dev/vda` 541065216 个 512B sector；EFI vda1 2048–2203647；root vda2 2203648–541065182，已到最后 usable sector，不能在 backing 未增长时 grow。

先确认 guest `blockdev --getsize64 /dev/vda` 实际为选定 274/290 GiB，再读取分区表并保存 UUID/GUID/EFI/起始 sector 证据。`sudo growpart -N /dev/vda 2` 预览只延长末尾；确认 start=2203648、EFI 和类型/GUID 未改变后，执行 `sudo growpart /dev/vda 2`。若 parent 未变大、预览异常、内核未重新识别新分区大小，立即停止，不继续 filesystem。

ext4（非 LVM/MD），本机已有 `/usr/bin/growpart` 与 `/usr/sbin/resize2fs`。分区增长确认后使用 `sudo resize2fs /dev/vda2`，不 mkfs、不重建文件系统、不对已挂载根盘执行修复式 fsck。若工具要求离线检查则停止，安排经验证的离线流程。

独立 GUEST_PARTITION_GROW_READINESS / FILESYSTEM_GROW_READINESS=READY 仅说明工具与对象匹配、步骤明确；所有全局门禁和更大的 parent 是实际执行的必要条件。这两个 READY 不许可现在执行。

## 阶段 6：扩容后验收（本轮未到达）

核对 backing/guest/partition/fs 容量、df/summary available、inode、内核无新增 I/O/ext4 错误、Harbor 7 ready、Jenkins 健康、3 nodes Ready 且 Lease 连续更新、PetClinic 3/3/HTTP200、所有保留 digest GET200。重新按**增长后容量**计算 frozen guard=15% capacity+12 GiB，保留 >=52 GiB preferred target；不能只满足旧49.78GiB或降低规则。备份继续保留，release/rollout=0。

当前 STOP 位于阶段 1 之前：无目标、容量不足、无已验证备份/恢复。下一步仅允许提供/验证适合的独立备份存储并补足宿主容量，或对明确可丢弃的宿主文件补所有权与用途证据后重算；不得清理 Harbor 镜像或活动 Colima 资料来绕过。
