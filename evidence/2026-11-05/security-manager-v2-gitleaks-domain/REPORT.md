# Gitleaks Clean 与本地域名定向收口

最终地址：http://security.devops.local:17862（带端口过渡入口，仅当前 Mac）。默认 curl 与 Node fetch 真实解析访问 HTTP 200；Node 最终请求约64ms。页面、CSS、JS、plugins/runs API 均200。没有 reverse proxy，没有80端口监听、没有安装DNS/代理组件。默认绑定始终127.0.0.1:17862。

Mac /etc/hosts 只新增目标域名：
127.0.0.1 security.devops.local
::1 security.devops.local

原始完整备份 /private/etc/hosts.security-v2-20261105-0724.before（0600），第一次成功修改前SHA256为94727d2c1713a792af2db7c06b1cd0dbcb3b921bf80f7b9f4b055466c8ed3f86。补IPv6前另备份 /private/etc/hosts.security-v2-dual-loopback-20261105.before。均通过macOS原生管理员认证完成，未收集密码。首次脚本在Python语法阶段失败，没有写入hosts；修正后先compile再执行。失败记录保留，未覆盖。

IPv4 hosts单记录时，dscacheutil/gethostbyname解析127.0.0.1，但默认curl/Node发生解析等待超时；定向取证显示IPv4查询约0.009秒，IPv6查询约5秒后返回IPv4-mapped地址。随后仅为同一目标加::1，本机双栈查询为127.0.0.1/::1；默认curl/Node成功。服务未增加IPv6监听：客户端如先选::1会连接失败后回退IPv4。未更改其他域名；剔除两条新增行后，hosts逐字节哈希与原始一致。此前成功/超时均作为真实观测保留，不宣称任何网络条件下永久稳定。

Web安全：新origins.mjs只增加精确security.devops.local:17862；Origin仍必须与Host完全一致；CSRF随机会话Token保持。真实HTTP验证页面200、目标域名同源请求202、错误CSRF403、错误Origin403、未知Host403。三个域名匹配单元测试通过。没有允许裸域名80、通配*.local、LAN或0.0.0.0。无需测试其他插件场景。

## 扫描仍未完成：准确阻塞位置

1. view/actions.mjs:50-52，预算使用字节单位os.freemem与statfs blocks*blocksize，无单位换算错误；load1 > cpuCount*0.75 或freeMemory<512MiB或freeDisk<512MiB即拒绝。实际目标域名Clean请求runId=web-a083a69c-3f1c-421f-ad13-bddd4b8b7b33，预算快照 {"load1": 8.3427734375, "cpuCount": 10, "freeMemory": 105709568, "freeDisk": 16662327296}。返回 LOCAL_RESOURCE_BUDGET_BLOCKED。Mac os.freemem是空闲物理页，不等于含可回收缓存的全部可用内存；memory_pressure -Q初次报告47%，不能仅用约70MiB断言系统内存耗尽。CPU load当时亦高于7.5准入线。未降低任何阈值；内存估算需Mac专用验证，不能靠替换指标强行放行。
2. view/actions.mjs:55、registry.mjs capabilityCheck：实际platform为darwin，三个现有native runner要求linux。Gitleaks-real.mjs:7-15还要求非root、NoNewPrivs、零CapEff、指定root-owned批准域，Mac不具备这些Linux语义。旧Linux成功记录不能证明Mac兼容。
3. 当前PATH、常规本地工具位置和索引未找到可信Mac Gitleaks executable。索引命中项是Dojo parser/receipt目录而非工具。现有tools-lock.json仅绑定8.30.1 linux/arm64镜像，不能把其摘要用于证明Darwin二进制来源。固定Mac Clean Fixture和可信适配也尚未建立。

本轮没有下载或执行未经验证的工具，没有创建不可信Mac适配器，没有伪装Linux，没有远程调用生产节点scanner。最小工具前置缺口：可验证来源的固定版本Darwin/arm64 Gitleaks二进制；即使具备该工具，也必须先满足资源预算并实现经验证的最小Candidate适配。没有通过删除校验消除BLOCKED。

## 实际执行结果

真实域名POST /api/run（Gitleaks Clean）已调用，产生新审计记录并在刷新后完全一致：web-a083a69c-3f1c-421f-ad13-bddd4b8b7b33。state=BLOCKED，Policy=null，evaluationCount=0，scannerExecuted=false。没有Gitleaks命令身份/退出状态、Raw Report或Result Digest（均NOT_EXECUTED/NONE）。请求身份为Mac普通用户UID501；不是scanner进程身份。审计digest不能当作Result Digest。没有继续Controlled Finding、Semgrep或Cosign。浏览器自动化不可用，BROWSER_CLICK=NOT_TESTED。

## 生产与回滚

生产只读复核HEALTHY：三节点Ready、PetClinic3/3、HTTP200、ArgoSynced/Healthy、Jenkins#270 SUCCESS。Deployment spec/image、V1 Summary、Trivy DB metadata、Docker daemon与原基线一致，socket0660。无K3s/Jenkins/Ingress/生产Gate变更、发布或rollout。

启动/停止/重启：node /Users/zhangsir/code/petclinic-platform-20261011/infra/security/manager-v2/view/control.mjs start|stop|restart。

域名回滚：sudoedit /etc/hosts，只删除本轮两条完整security.devops.local映射行；保留所有其他行。再sudo dscacheutil -flushcache与sudo killall -HUP mDNSResponder。不直接用备份覆盖含他人后续修改的hosts。原始备份供核对。服务停用只用control.mjs stop。

本轮真实扫描目标仍INCOMPLETE。停止，不继续其他工具/发布。
