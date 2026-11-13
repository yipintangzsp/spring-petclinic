# SOPS/age真实受控执行：安全预检停止

**最终SOPS/age状态保持NOT_TESTED，历史真实负例DEFERRED_REAL_NEGATIVE_EVIDENCE。没有执行真实受控Gate，不能提升为VERIFIED。**

## 已执行的只读检查

- 原secrets-gate.mjs仍固定读取petclinic下三个Secret和devsecops-system下一个Secret；readOnly只关闭apply，仍会读取Secret data。因此禁止用生产集群跑正例，即便密文和age key换成测试数据也不安全。
- 本机没有sops/age可执行文件；生产工具锁指向现有Jenkins工具路径。没有安装软件或导出生产key。
- 发现已有kind-my-multi-node-cluster和orbstack两个context。经正常网络访问检查，kind的127.0.0.1:63731实际connection refused；default及desktop-linux Docker socket均不存在。未启动/重装整个Docker环境或创建新集群。
- 名为orbstack的context不能按名称认定为非生产。只读比较该context与严格SSH已验证的devops主机上的kube-system namespace UID，两者均为639e5426-bc1f-4d37-a844-6a31b7685744，确认是同一集群。仅查询namespace元数据和节点名称，没有读取Secret。

## 为什么停止

原Gate没有可注入测试namespace/target的输入。改Gate违背本轮约束；在同一主集群给固定生产名称创建测试Secret会触及现有对象；用kubectl stub/VM模拟Secret响应又不能声称真实prerequisite/Kubernetes验证。现有独立测试集群不可用，不能在当前授权边界内安全完成真实正例。

没有把连接检查当作Gate prerequisite执行证据，没有继续制造真实负例。没有新key、密文、fixture、Kubernetes资源、权限或持久服务，故无清理对象；没有使用/打印/导出真实生产Secret或age私钥。原Gate和实际Summary未修改，无发布或rollout。

## 12项结果

1. real controlled executions：0。
2. positive：0。
3. negative：0。
4. prerequisite/error Gate executions：0（只做环境可达性预检）。
5. old Gate decisions：无，未运行。
6. Policy standard decisions：无，未对未执行结果伪造判定。
7. differential：NOT_TESTED。
8. secret leakage：生产Secret读取0、输出0、key生成0。
9. cleanup：NOT_APPLICABLE，未创建fixture或资源。
10. SOPS/age：NOT_TESTED。
11. Policy tests：此前86/86 PASS；本轮未新增或重跑单元测试，不冒充真实执行。
12. remaining gap：真实隔离执行环境，以及在其中运行冻结Gate所需的既有身份/Lease/目标fixture和工具能力；之后仍须真实正负例、同事实差分和清理证明。

最小下一步是先具备真正隔离、可丢弃的Kubernetes执行环境及既有授权能力，再重新核对是否能原样执行Gate。现有orbstack context不得用于fixture；不通过扩大主集群权限或修改Gate绕过此问题。本轮停止，不进入其他安全来源。

机器可读证据：evidence/2026-11-01/sops-controlled/acceptance.json。
