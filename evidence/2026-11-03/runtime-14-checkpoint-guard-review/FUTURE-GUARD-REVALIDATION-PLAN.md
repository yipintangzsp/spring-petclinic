# 待单独批准的磁盘 guard 受控复验计划

本轮仅设计，执行次数为 0。当前 guard `capacity*0.15 + 12 GiB` 保持原样，`TRIVY_RESUME_ALLOWED=false`。不提出直接替换用的新阈值。

1. 使用独立、可销毁的 VM/经恢复验证的离线克隆，具备充足的独立物理磁盘与备份。保留相同 k3s/容器镜像/Trivy 二进制 SHA、同一 `scanner-db-refresh.mjs` SHA、DB schema、运行 UID、缓存路径、ext4/local-path/overlay 拓扑及原 guard。隔离 kubeconfig、API、registry 和所有凭据；证明目标不是生产集群。原 guard 自身仍须满足，不通过降低容量/储备或伪造 stats 准入。
2. 在执行前取得与实际冻结二进制版本相符的源码，核对 OCI 下载、解压、DB 安装/替换、rename/copy、open-unlinked 文件、失败清理路径。源码必须绑定精确版本/源码或镜像摘要；未能确认前不把 atomic rename 当成既有保证。
3. 以独立下载批准取得同一次受控环境所需的正式 manifest/blob，记录 digest/压缩大小/解压文件大小、before metadata、原有 DB 的逻辑及实际分配块。不得使用历史 archive 的大小代替当前内容，不改 freshness/manifest checksum/官方来源与路径规则。
4. 运行**原** release-preflight / `ensureScannerDatabases` / `scannerRefreshIO`，使用隔离环境中同名 `devops` 及真实 owned heavy Lease。分别验证 db-only、java-only、两者过期串行；当前 guard 和错误处理必须原样执行。helper 等待前一项完成才执行下一项。
5. 高频测量（建议 100–250ms，并记录采样精度与漏峰风险）：nodefs/imagefs可用量、Jenkins manifest临时目录、scanner容器 `/tmp`、cache PV、overlay upper、旧/新 DB inode 和分配块、打开后unlink文件。用 fsnotify/进程 syscall trace 及文件分配变化补足 `du` 的漏峰；跟踪跨挂载 rename/EXDEV 或复制行为。整个 VM 的背景写入独立测量，不能全部归因 DB。
6. 输出 free-before / used-before、download growth、extract growth、阶段共存集合、peak/最终占用/旧文件何时释放。区分绝对 used peak 与从初始状态新增的 free-space需求；多数据库串行用阶段最大共存值，不将不共存峰值直接相加。区分PVC bind、overlay和其共同宿主文件系统，防止重复计数。
7. 仅在隔离副本中执行受控错误：download中断、校验失败、CLI timeout、提取/安装失败、报表/metadata错误；确认原metadata错误不会变fresh、原DB保留/破坏的真实行为、owner限定进程清理与重试边界。不在生产制造ENOSPC/OOM。
8. 实验完成验证内容和失败清理语义、原 freshness 与签名/manifest校验、old Gate/Policy兼容，销毁隔离环境。保存全部时序原始样本及采样误差/观察上界。
9. 评审时保留平台 `15% capacity + 8 GiB` 停止线，将当前4GiB刷新增长预留与实测**额外峰值**比较，再单独批准任何公式变更。来源、必要系统安全余量、并发/日志增长、宿主 qcow2/APFS COW/备份预算均须独立证明。不得因正常样本较小自动下调。

禁止本轮执行：tmpfs/RAM disk、迁移cache/DB路径、修改PVC/quota/预留块、下载DB、构建新环境、刷新DB、调整代理或开启新listener。任何替代临时存储未来还须独立证明内存预算、OOM风险、同等atomicity及失败语义，不属于此计划已批准内容。
