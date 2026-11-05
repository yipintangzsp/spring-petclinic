# Security Manager V2 — 本地只读结果页

访问 <http://127.0.0.1:17862>，仅在启动服务的 Mac 上可访问。无需新依赖，使用现有 Node.js。

```sh
cd /Users/zhangsir/code/petclinic-platform-20261011
node infra/security/manager-v2/view/control.mjs start
node infra/security/manager-v2/view/control.mjs status
node infra/security/manager-v2/view/control.mjs stop
node infra/security/manager-v2/view/control.mjs restart
node infra/security/manager-v2/view/verify.mjs
```

默认展示最近三插件全部完成的 Service 项目记录，可切换最近身份拒绝、Java 正向、三插件负例、禁用、超时及不可用记录。来源为 `evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs/attempt2-*` 的固定允许列表，不执行新扫描。REAL 指历史受控真实工具执行；页面读取方式为 REPLAY。Cosign 仅受控离线 Blob 验签，不代表生产镜像信任验证。禁用与错误没有 Policy decision，不能视为 PASS。

展示前验证 summary/result/raw 的封存文件哈希、结果自身 digest 与 summary 绑定；数据不完整时显示 UNAVAILABLE。当前哈希匹配不等于恢复原有历史完整性，`ORIGINAL_EVIDENCE_INTEGRITY=FAILED` 保留。只输出允许字段，不展示 findings 内容、不提供任意文件下载。

Consumer 区独立读取先前 Loki、Dojo HTTP 协议测试的真实回执，明确为 MOCK + REPLAY，显示独立 Run ID 和来源。它们不属于当前所选插件 run，未向真实远端投递，也不拼为 same-run 16/16。

只接受本机 Host 与同源 GET/HEAD，没有写 API、自动轮询、生产连接或生产凭据。服务仅绑定 127.0.0.1。PID、启动日志保存在本用户临时目录的专用 0700 子目录，停止时核对随机 instance 与 PID，拒绝全局 kill。停止后代码和证据保留，可再次启动；不会安装常驻启动项。

生产 Manager NOT_ACTIVE；Jenkins V2、Trivy、Dojo runtime 与 Summary V2 尚未闭环。Canonical Runtime 保持 14/16。Grafana 健康 GET 返回 200，但未认证用户/数据源 API 返回 401，因此未写入或覆盖现有 Dashboard。

回滚：运行上面的 stop 即停用本地入口。无需恢复生产配置，本页面不修改生产状态。不要删除或重写来源证据。
