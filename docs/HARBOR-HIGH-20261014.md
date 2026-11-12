# Harbor High 漏洞处理记录 · 2026-10-15

2026-10-16 更新：#145 再次完整发布成功（504.681秒），源码 `092738cb3dacdedd59bce2c1609df91c71af7dfd`，晋升 `06f1e2b45e36b7771ce2e933d2cfaebbdc01819f`，镜像 `sha256:a78288f407c99ebcb7332441501063dc878a41d9390599c673bd864eb49158c5`。两架构仍各 Critical0/High0/Medium169/Low15；报告ID和子摘要见私有 `build-145-harbor.json`。固定安全包现在使用构建用户持久内容摘要缓存，每次复用重新 SHA256 校验，缓存错误或下载不匹配均拒绝；32项Node测试含3项缓存安全回归。10包离线缓存实测通过。以下 #142 为首次关闭 High 的历史证据。

最新#147完整SUCCESS，472.903秒；源码04f86c9643d1a9aff1b236ef40bb590d002b628e，晋升c9d4ff6c8f9a170f2b71a5d236c49f76a75cc6ed，OCI摘要sha256:db78a09a6036d9dd2d49002bce90805f0bfd886778eb145fcb636dae3ba473ce。2026-10-16 00:53–00:54 UTC双架构Critical0/High0/Medium169/Low15；报告ec953a11-b7c5-47eb-94e3-915e8fb91517（amd64）、ef65224d-124c-4a52-b474-19a1075ff054（arm64）。范围为本次PetClinic发布镜像，不代表Harbor服务本体或全平台所有镜像零漏洞。证据build-147-harbor.json。

Jenkins #142 完整发布成功，源码 `a6559d48a3037383c46b04a83e4202b43c19e260`，OCI index `sha256:76b6716b3404b554ebd0bd3d91ca9e932efc400e3d766d22b20d0d506b35f6d5`。2026-10-15 12:28 UTC 的双架构扫描均 Critical 0、High 0、Medium 169、Low 15，共 184 项，其中 134 项标为 fixable。**本轮关闭 High，不代表镜像无漏洞**；Medium/Low 的批量升级仍需后续兼容性验证，不能以扫描成功替代修复。

Trivy 为 0.69.3，原生 ARM adapter 基于官方 v0.35.1 源码。漏洞库以官方 GHCR OCI 摘要核验后通过 Trivy 原生下载流程预热，UpdatedAt=2026-10-15T07:10:08.755380281Z、NextUpdate=2026-10-16T07:10:08.755380121Z，未冻结更新或修改时间。Java DB 更新至 10 月 14 日版本、10 月 17 日到期。现有 StatefulSet 最小补丁将单次扫描超时从 5m 调整至 10m，保留原 PVC 和更新机制；网络仍依赖 Mac 出口代理，不宣称独立稳定出口已解决。

固定原双架构基础镜像摘要，官方包 URL、各架构 SHA256 及版本记录在 `infra/runtime/openssl-packages.json`。OpenSSL 三包为 3.5.5-1ubuntu3.7；curl/libcurl4t64 为 8.18.0-1ubuntu2.8。构建前有界下载与 SHA 校验，镜像内 dpkg 安装，未修改运行中容器或重写全局基础镜像标签。只移除 Java ENTRYPOINT 和应用未调用的 Pebble 工具。

## 原 #134 两架构各 14 项 High 的逐项关闭

原始 Harbor v1.1 报告不含二进制 Target 路径，后续对镜像实际文件的独立检查确认 /usr/bin/pebble v1.32.1 含 Go 1.26.5 build 标识、且非 dpkg 所有。该定位证据与最终扫描共同支持处理结论，不伪称原报告已经提供二进制路径。

|CVE|受影响包|当前版本|扫描报告修复版本|处理/限制|
|---|---|---|---|---|
|CVE-2026-84782|libssl3t64|3.5.5-1ubuntu3.3|3.5.5-1ubuntu3.6|已随 #142 发布：按架构/SHA256 安装 Ubuntu 官方安全包 3.5.5-1ubuntu3.7；两架构新库报告均无此 High。|
|CVE-2026-56853|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-56858|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-84782|openssl|3.5.5-1ubuntu3.3|3.5.5-1ubuntu3.6|已随 #142 发布：按架构/SHA256 安装 Ubuntu 官方安全包 3.5.5-1ubuntu3.7；两架构新库报告均无此 High。|
|CVE-2026-56859|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-84782|openssl-provider-legacy|3.5.5-1ubuntu3.3|3.5.5-1ubuntu3.6|已随 #142 发布：按架构/SHA256 安装 Ubuntu 官方安全包 3.5.5-1ubuntu3.7；两架构新库报告均无此 High。|
|CVE-2026-39821|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-33818|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-46600|stdlib|v1.26.5|1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-56860|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-56862|stdlib|v1.26.5|1.25.13, 1.26.6, 1.27.0-rc.3|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-78667|stdlib|v1.26.5|1.26.9, 1.27.2|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-78669|stdlib|v1.26.5|1.26.9, 1.27.2|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|
|CVE-2026-97031|stdlib|v1.26.5|1.26.9, 1.27.2|已随 #142 发布：确认未使用的 /usr/bin/pebble 含 Go 1.26.5，移除该工具；两架构最终报告均无此 High。|


## 新库在 #141 发现的额外 High

|CVE|包|#141 版本|官方修复版本 / #142 实装|结果|
|---|---|---|---|---|
|CVE-2026-92392|curl|8.18.0-1ubuntu2.3|8.18.0-1ubuntu2.8|#142 两架构均关闭|
|CVE-2026-92392|libcurl4t64|8.18.0-1ubuntu2.3|8.18.0-1ubuntu2.8|#142 两架构均关闭|

私有证据：`build-142-harbor.json`（两个子摘要、report_id、时刻及数量）、`harbor-high-20261015`（原报告、官方包元数据与文件取证）、`trivy-warm-20261015`（官方 OCI 摘要、原生预热结果）、`trivy-timeout-20261015`（最小补丁前后对象与资源锁记录）。#135/#137 中止及 #140 数据库下载超时均保留为失败历史；#141 已成功发布但仍有两项 High，#142 才是本轮 High 关闭版本。

## 2026-10-22 #165最新发布范围

本次完整发布源码ecbae16a42c26118630784d14a7031a460bb21cd、晋升cc9adad3fb37c5cbe5fd0def8abf70a190075e97、OCI index sha256:1cc18108498cfe1d5fcecca40990077dfa483b928cf5f150df54d03fda154e98。两架构扫描2026-10-22 08:52 UTC完成：各Critical0/High0/Medium176/Low15，总191，其中134可修复。amd64子摘要87dac7d9fece9c6c44ff6498ec12acb7ed924e3c3ab5ddbf5d682d7402a43144；arm64子摘要226423bd461ebe1fd7cf312f890abab2274a3eadaa1121f59cc58c762f68d8eb。原始报告见私有analytics-release-20261022/ci-165/harbor.json。中低危仍在，不能把扫描成功写为无漏洞；范围仅本次PetClinic镜像，不代表Harbor服务本体及新控制器镜像全部通过零漏洞审查。
