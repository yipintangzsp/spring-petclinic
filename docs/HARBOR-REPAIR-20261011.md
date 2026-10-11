# Harbor 最小修复与扫描数据库维护

Redis AOF 原件 13,195,889 字节，SHA256 `c4f7d5ca08e84f0db8c7e2d41d62df87fc2b61c47f02a892407cc6a925a10847`。独立副本验证 RDB 校验及有效 AOF 前缀正常，末尾 135 字节全部为零。用户单独授权后，保存所有 AOF/RDB/manifest 原件，仅截除 135 字节；修复后 SHA256 `6bd2a1dbac2e2fefa73e39ea065575535198c357cb5f28a0b905926354bad0d4`。Redis PONG、BGSAVE、AOF 写入状态均正常，core/jobservice 恢复。

原件和演练副本保存在服务器私有目录 `/opt/petclinic-observability/backups/platform-20261011/redis-original`、`redis-rehearsal`。恢复原件会重新引入已确认损坏尾部，不应作为常规回滚。任何进一步修改持久化文件必须重新取证；不得自动截断其他文件。

构建 #123 已完成双架构镜像推送及摘要校验，但扫描被首次数据库下载阻塞：Trivy 0.69.3 从 mirror.gcr.io 下载漏洞库在五分钟超时。生产更新未开始。保留失败构建、扫描日志和镜像。

数据库修复采用官方支持的缓存填充方式：从 GHCR 获取 OCI manifest，流式下载每个数据库 blob，验证完整 SHA256 和字节数，再在停止 scanner 后解包至原 PVC。仅接受数据库文件和 metadata.json；不绕过 TLS、漏洞扫描或数据库更新。Trivy 0.69.3 要求手工填充时记录非零 `DownloadedAt`：已分别使用文件实际下载完成时间 `2026-10-11T10:43:52.173732Z`、`2026-10-11T10:48:25.343230Z`，原始 metadata 单独保留，UpdatedAt/NextUpdate 均不修改。此前零值导致 #125 再次下载，已在发布前停止该构建。漏洞库和 Java 库分别存放于既有缓存的 `trivy/db`、`trivy/java-db`，保留修改前缓存和下载摘要、元数据。

重启时发现原公开镜像标签需要重新拉取，而既有 local-registry 已保存完全相同的 manifest `sha256:5c6f7162804cd94d41672a694579f136ccc9730d024dda9ad24e0f42bdae6f36`，config digest 与修改前容器的 imageID 一致。改为该本地镜像摘要，避免外部拉取阻塞。实际镜像架构为 AMD64，现有 ARM 节点使用既有模拟支持；不应将 scanner 写成原生 ARM64。版本保持 v2.14.3 / Trivy 0.69.3。

缓存填充的瞬时内存 full PSI avg10 为 12.74，触发 >5 的停止条件；业务健康请求仍全部为 200。暂缓新增重任务，待连续样本压力回落并确认 scanner 就绪后恢复。完整数据库元数据、资源样本和修改前配置均保留于私有证据目录。

既有 StatefulSet 最小配置变更：

```sh
kubectl -n harbor set image statefulset/harbor-trivy \
  trivy=127.0.0.1:30050/goharbor/trivy-adapter-photon@sha256:5c6f7162804cd94d41672a694579f136ccc9730d024dda9ad24e0f42bdae6f36
kubectl -n harbor set env statefulset/harbor-trivy \
  SCANNER_TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db \
  SCANNER_TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db \
  SCANNER_TRIVY_TIMEOUT=15m0s
```

`SCANNER_TRIVY_SKIP_UPDATE`、`SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE` 保持 false；缓存不是永久冻结数据库。下一次更新仍需访问官方源。监测 metadata.json 的 UpdatedAt/NextUpdate，不得将过期数据库扫描宣称为最新扫描。完整工作负载备份保存在私有证据中；配置回滚可恢复原仓库列表和 `5m0s`，无需删除数据库缓存或业务数据。

流水线只依次请求 ARM64、AMD64 运行时子镜像扫描，不再同时请求 OCI index 和子镜像。两份真实扫描均成功后才允许 GitOps promotion。完成扫描不等于不存在漏洞；报告保留实际严重度和数量，发布身份以完整 OCI index digest 固定。

参考：[Trivy 官方缓存填充与自托管数据库文档](https://trivy.dev/docs/latest/guide/advanced/self-hosting/)。实际修复及后续发布结果以最终验收记录为准。

对应版本行为依据：[Trivy v0.69.3 数据库校验源码](https://github.com/aquasecurity/trivy/blob/v0.69.3/pkg/db/db.go)。
