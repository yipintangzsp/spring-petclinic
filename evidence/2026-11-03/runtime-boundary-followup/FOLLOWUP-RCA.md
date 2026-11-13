# Runtime boundary follow-up：只读根因定位

本轮未触发Jenkins、未修改代码/Gate、未更新scanner缓存、未删除镜像、未修改proxy或共享webhook。原120文件证据封存保持不变。完整边界仍13/16，四项最终verdict均INCOMPLETE。

## Trivy根因

现有Mac IP仍192.168.1.238。xray实际仅监听127.0.0.1:10808；通过回环代理请求GHCR /v2/成功到达并返回认证challenge401，通过LAN代理地址连接失败（curl exit7）。不是IP漂移，也不能把401误报为网络失败。Harbor仍指向LAN地址，故下载DB连接被拒绝。两个DB NextUpdate均为2026-10-31，早于本轮日期。

## 已验证的替代路径与新阻塞

已用仓库原scannerRefreshIO.upstream读取并校验官方两个manifest的header/content digest及layer media/size；现有配置镜像源https://ghcr.nju.edu.cn/v2/从devops主机直连HTTP200。只做manifest/入口可达性验证，未下载layer，未证明完整blob链路。

原scanner-db-refresh.mjs要求available >= capacity*15% + 12GiB。实际容量251.86GiB，可用43.44GiB，需要49.78GiB，短缺6.34GiB。node.fs与imageFs均未满足。未调用缓存更新、未改freshness/资源阈值，也未用skip-db-update。

## 资源盘点

读取devops的113个镜像、163个container记录，均未删除。存在无现有container引用的镜像，但可能是离线前置工具或rollback版本；镜像size还共享layers，不能简单相加当作可回收空间。disk-ownership.txt为低IO优先级、35秒上限盘点输出，若未输出完整各路径，不能当作完整磁盘归因。

## 尚未解除

- Trivy：先满足原磁盘余量，再执行既有官方DB刷新前置逻辑；即使一次刷新成功，Mac代理仅loopback的长期依赖仍需独立修复，不能称永久解决。
- Cosign：独立namespace不被现有共享webhook选择；allowlist内原有namespace另有生产trust或镜像仓库约束。不能改Gate/绕过策略来制造通过。
- DefectDojo：完整current report/import/reimport链仍受Trivy native report缺失阻塞；既有隔离身份证明有效，未重建已清理身份或伪造导入。

## 最小下一步

先只读细化磁盘占用与保留策略，形成明确到路径/digest且排除在用/回滚/离线必需镜像的回收清单；或明确扩容方案。共享proxy监听/webhook改动需独立限定变更范围与回滚，不能作为本轮小修自行实施。暂不重跑扫描/发布。

生产复核：petclinic-ci仍#270 SUCCESS，V1 Summary SHA保持ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8，三个node Ready，heavy Lease已释放。

```text
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```
