# Harbor 最小修复与扫描数据库维护

Redis AOF 原件 13,195,889 字节，SHA256 `c4f7d5ca08e84f0db8c7e2d41d62df87fc2b61c47f02a892407cc6a925a10847`。独立副本验证 RDB 校验及有效 AOF 前缀正常，末尾 135 字节全部为零。用户单独授权后，保存所有 AOF/RDB/manifest 原件，仅截除 135 字节；修复后 SHA256 `6bd2a1dbac2e2fefa73e39ea065575535198c357cb5f28a0b905926354bad0d4`。Redis PONG、BGSAVE、AOF 写入状态均正常，core/jobservice 恢复。

原件和演练副本保存在服务器私有目录 `/opt/petclinic-observability/backups/platform-20261011/redis-original`、`redis-rehearsal`。恢复原件会重新引入已确认损坏尾部，不应作为常规回滚。任何进一步修改持久化文件必须重新取证；不得自动截断其他文件。

构建 #123 已完成双架构镜像推送及摘要校验，但扫描被首次数据库下载阻塞：Trivy 0.69.3 从 mirror.gcr.io 下载漏洞库在五分钟超时。生产更新未开始。保留失败构建、扫描日志和镜像。

数据库修复采用官方支持的缓存填充方式：从 GHCR 获取 OCI manifest，流式下载每个数据库 blob，验证完整 SHA256 和字节数，再在停止 scanner 后解包至原 PVC。仅接受数据库文件和 metadata.json；不绕过 TLS、漏洞扫描或数据库更新。漏洞库和 Java 库分别存放于既有缓存的 `trivy/db`、`trivy/java-db`，保留修改前缓存和下载摘要、元数据。

既有 StatefulSet 最小配置变更：

```sh
kubectl -n harbor set env statefulset/harbor-trivy \
  SCANNER_TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db \
  SCANNER_TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db \
  SCANNER_TRIVY_TIMEOUT=15m0s
```

`SCANNER_TRIVY_SKIP_UPDATE`、`SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE` 保持 false；缓存不是永久冻结数据库。下一次更新仍需访问官方源。监测 metadata.json 的 UpdatedAt/NextUpdate，不得将过期数据库扫描宣称为最新扫描。完整工作负载备份保存在私有证据中；配置回滚可恢复原仓库列表和 `5m0s`，无需删除数据库缓存或业务数据。

流水线只依次请求 ARM64、AMD64 运行时子镜像扫描，不再同时请求 OCI index 和子镜像。两份真实扫描均成功后才允许 GitOps promotion。完成扫描不等于不存在漏洞；报告保留实际严重度和数量，发布身份以完整 OCI index digest 固定。

参考：[Trivy 官方缓存填充与自托管数据库文档](https://trivy.dev/docs/latest/guide/advanced/self-hosting/)。实际修复及后续发布结果以最终验收记录为准。
