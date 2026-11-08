# 独立Trivy环境的最小实施边界

目标仅devops/192.168.64.11；现有zhang管理通道可初始化。执行身份security-trivy不授予sudo、Docker组、Kubernetes或生产凭据。系统分配未占用UID/GID；独立root-owned工具/固定项目配置，账户私有缓存/输出。专用SSH公钥仅restrict+固定ForceCommand；禁止PTY、转发、用户环境和任意命令。仅接受固定项目、场景、合法Run ID；仓库/Index Digest由root-owned配置确定，解析后绑定单个ARM64子Manifest并记录映射。

工具计划0.76.2，需将官方校验文件及归档/API摘要交叉验证后才安装；从官方OCI源取得vulnerability DB与Java DB，记录OCI Manifest/Layer Digest、文件SHA256及元数据。与生产缓存完全隔离；更新失败或过期必须拒绝，不回退生产/旧DB；不修改DNS/代理/系统信任。若可信准备产生较大资源成本先停。

正式扫描必须经统一开关/项目授权/资源准入；固定参数、输出上限、超时与进程组清理。最多一次；Policy已有Trivy严重级别规则不得放宽；不得触发其他插件。

当前状态：尚未实施远端写入。先补齐该候选的已授权只读pull身份引用；需要新Harbor Robot时另行批准，不能复用生产管理员/发布凭据。镜像准入未过，不提供虚假可运行开关。

回滚（仅后续实际创建后适用）：停用Trivy独立开关，撤销本轮专用SSH公钥/短期Harbor凭据，确认无子进程后移除本轮独立目录和新账户；保留历史Artifact，不更改其他账户、sshd全局配置或生产服务。
