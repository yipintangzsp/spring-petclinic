# Kubescape — W12 结论
- MANAGEMENT: PARTIAL -> VERIFIED（G-K2 关闭）。view 接线 + registry/core/loki/loki-event 接线增量一并提交 c52aecca。POLICY 仍 PARTIAL（U5 冻结 AUDIT 口径，未动）。
- 复验：view-driver clean web-457955ed COMPLETED/PASS（findings=1260）；finding web-d3e40b7d COMPLETED/PASS + auditDisposition=WARN、violating 创建/删除/verifiedGone、findings=1285、Loki DELIVERED/VERIFIED；关态零执行；恢复 READY。单测 8/8。
- 前提恢复：W3 收尾删除的测试命名空间 kubescape-v2-test + Role/RoleBinding（W3 rbac.yaml 原定义子集）已按原件恢复并保留为复用测试基础设施（raw/kubescape-testns-restore.yaml）；首跑 VIOLATING_CREATE_FAILED 即因此，恢复后通过。另一次 RESOURCE_BUDGET_BLOCKED 为 devops 负载尖峰（并行线），回落后通过。
