# 回滚与停止线

本轮仅只读取证，没有删除、prune/GC、缓存刷新、proxy变更、服务重启、发布或rollout；无需恢复任何资源。

- 所有UNKNOWN、offline、rollback、current/candidate镜像保留；没有提供可执行的危险清理命令。
- 7项cleanup安全断言通过不等于真实空间回收完成。
- proxy方案B尚未实施；进入该阶段前须另存配置hash/必要私有备份、精确bind及来源ACL、专属进程nonce/PID与解除监听命令。撤销不得停止原xray或修改其无关routing。
- 未达到磁盘干运行准入，不能先执行小额清理后再升级至高风险目标；不能降低原15%+12GiB。
- 下轮若采取受支持registry生命周期/GC或磁盘扩容，须先给出引用保留清单、预期可回收实量/备份恢复和影响范围；禁止手动rm blobs及业务PVC。
