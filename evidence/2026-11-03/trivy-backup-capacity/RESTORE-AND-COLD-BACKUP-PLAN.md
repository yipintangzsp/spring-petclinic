# 本轮备份与恢复计划：受条件约束，未执行

当前阶段只允许备份前准备和满足条件后的冷备份；**本轮即使全部 READY 也禁止扩盘**。当前没有适合的独立备份目标、足量安全回收集或已验证备份，所以停在删除和关机之前。本计划不是可直接运行的脚本。

对象：VM devops，UUID `4C8DEDBC-D2FB-43F6-99EC-C2C6F9C1FF46`；原路径 `/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm`；磁盘 `Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2`，另含 `config.plist` 与 `Data/efi_vars.fd`。UTM4.7.5，原VM22GiB RAM。

## 目标与格式接受条件

优先格式 FULL_COLD_UTM_BUNDLE_COPY。当前 selected destination=NONE；不虚构目录。候选必须实际独立且稳定挂载，实际权限及大文件往返、文件系统能力、独立读取恢复、持续可用窗口通过验证。若是网络目标，还需持续连接/大文件/超时行为和权限稳定证据；不能仅用touch或ping接受。

保守 full-copy 预算约342.69GiB。已分配约205GiB可作为稀疏方案的调查依据，**不是不可变冷备份大小或目标可容纳证明**。只有停机源区间重新盘点、目标稀疏保留、全量hash及恢复重新展开都验证后，才能按真实实际占用降低预算。压缩比未实测，不以205GiB可压至小于53GiB为前提；也不宣称342.69GiB是任何格式都不可避免的下界。

全bundle复制工具拟用现有 `/usr/bin/rsync -aS --extended-attributes SOURCE_BUNDLE/ PRECREATED_EMPTY_BACKUP_BUNDLE/`。本机小型同APFS工具实验在上一轮已通过，**尚未验证新的目标**。不得用同名不存在的file目标触发错误目录映射，不用--delete、不覆盖旧备份。外盘ACL/owner/xattr等必要属性必须验证，命令与版本记录到实际执行receipt。目标与源绝不能是同一文件或可写hardlink。

## 删除门禁

候选要求 path/size/owner/tool/lastUse/recovery/reproducible/project-use/current FD proof齐全，UNKNOWN保留。源仓库、权威evidence、活动UTM、currentqcow2、活动Colima、凭据、备份/rollback材料均排除。所有已证明安全候选的**不重叠合计**必须达到所需回收量才允许开始；本轮实际SAFE_RECLAIM_TOTAL=0，故删除0、无增量批次。

未来若有足量证据，按Tier1→2→3逐批，到达实际计算目标即停，不自动进入Tier4。每批重新测宿主free并检查Colima/Docker、UTM、Jenkins、K3s、PetClinic与源码/证据hash；测得free差异不能自动归因删除，receipt必须列实际删除路径与字节。目标至少37GiB（独立外盘+16方案），优先45–50GiB；若所选备份临时空间要求更多则上调，不用固定37掩盖额外需要。

## 冷备份前提与占用检查

只有目标已验证且宿主状态可接受，才建立排它维护窗口：Jenkins所有相关job空闲并防新任务进入，validation空闲、HarborGC/registry维护/TrivyDB更新均停止、无security测试负载。当前 API idle 结果不是独占窗口证明；本轮未quietDown或停止任何组件。

记录原platform健康、三节点/Lease、Pod/Endpoint、HTTP、Harbor与protecteddigest、Jenkins#270、V1SHA及VM配置身份。冷关机影响控制平面及同VM平台组件，时间需未来实测吞吐预算，不承诺零中断。

用既有严格校验hostkey的SSH干净关机guest；不改SSH校验。断开SSH不证明停机。要求 UTM=STOPPED、目标QEMU/QEMULauncher进程退出、精确qcow2无任何writer/openFD；检查fresh、覆盖全部相关进程、没有权限错误。只查名为qemu-system的进程不足，因为当前writer是QEMULauncher。任意缺证据/占用均ABORT，不force-share。

## 备份与校验

静态源完整bundle复制到已验证新空目录。记录命令、toolversion、起止UTC、本机/目标free、实际byteswritten/allocated/logicalbytes、exit/stderr。源不resize/convert/commit/rebase/amend、不制造快照写入。

逐文件比对清单、大小、权限/所需属性、配置UUID/磁盘绑定/EFI以及SHA256，不能跳过大盘hash；确认无遗漏、截断、copyerror和原文件可写共享。对**离线备份副本**执行 `qemu-img info --output=json <backup-qcow2>` 与 `qemu-img check -f qcow2 <backup-qcow2>`，不用修复参数，不在活动源CHECK。全部通过才BACKUP_VALIDATION=VERIFIED；否则保持INCOMPLETE/FAILED，禁止扩盘。

## 恢复与隔离验证

恢复预定终点是上面精确原bundle路径；实际source backup path不存在，当前RESTORE_READINESS=NOT_READY。故障恢复：停止目标VM并证明无FD→在已证明有容量时保留坏副本/日志→验证冷备hash→恢复bundle及config/EFI/drive身份至原路径→UTM打开/重新附加→启动→验证hostname/root/ext4/kernel I/O、网络/DNS/API、k3s/Lease、3nodes、Jenkins/Harbor、PetClinic3/3/Endpoint/HTTP200与protecteddigest。不能以缩盘代替备份恢复。

不得覆盖当前VM来测试恢复。若安全且资源允许，隔离测试使用独立复制目标、新UUID/MAC，**禁用全部网络接口**，禁用共享宿主可写目录及全部生产数据卷/其他生产写入通道；不得接触liveK3s/DB/Harbor/Jenkins。原22GiB＋clone22GiB＋Colima2GiB已超过宿主32GiB且未计OS，因此当前不尝试同时启动clone。

若无法安全隔离启动，实际备份全量hash/info/check通过可记OFFLINE_IMAGE_VALIDATED，并公开“未验证boot”的限制；不能冒充ISOLATED_BOOT_VERIFIED。仅活动源metadata不算备份METADATA_ONLY。本轮无备份，RESTORE_VALIDATION_LEVEL=NOT_VALIDATED。

完成冷备后启动**原VM**，保持原身份，验证hostname/root/network/k3s/3nodes/Jenkins/Harbor/PetClinic3/3/HTTP200。原VM正常重启不能当作备份恢复成功。

## 本轮停止点

当前：目标未验证、宿主free低于37GiB、安全回收0。未关机、未复制、未恢复、未重启原VM，也未执行扩盘。原VM保持运行，按实际只读结果验收。

后续如所有备份、容量、恢复及维护门禁均满足，只重新计算PRE-EXPANSION READINESS并STOP；resize/partition-grow/fs-grow均留到下一独立变更。此前分区/ext4步骤仅为计划READY，不是执行授权；它们仍依赖全局门禁和实际更大的parent。完整上一轮计划位于 `../trivy-pre-expansion/MAINTENANCE-RESTORE-RESIZE-PLAN.md`，只读引用，未修改。
