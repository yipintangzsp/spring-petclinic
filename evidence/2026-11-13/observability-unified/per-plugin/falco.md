# Falco — W12 结论（G-F3 BLOCKED，不假接线）
- MANAGEMENT: 仍 PARTIAL。
- BLOCKED 精确原因：(1) falco-real.mjs 无 falcoUiCase 导出（W8 已核，本波复核属实）；(2) falco runner 的执行输入为 {testPod, windowEndMs}，testPod 须匹配 ^falco-v2-[a-z0-9-] 且 windowEndMs 须在采集窗口 ±1h 内，这两个输入无法由 view 的固定提交契约 {pluginId, projectId?, scenarioId} 承载（validateRequest 只接受这三个键）；(3) 生成 testPod 需要在 devsecops-test 建 Pod 的集群写通道，Mac view 进程不持有该通道，falco 采集 SA 经 W8 实测 can-i create pods=no，view 的固定夹具模型也没有 Pod 生命周期通道。
- 结论：不把 falco 加入 view ids/capability（那将是无真实用例的假接线）。待办建议 G-F3a：先在 falco-real.mjs 设计 falcoUiCase（由 runner 侧受限入口负责测试 Pod 的建/删与窗口生成），或扩展 view 提交契约后再接线；与 U3（Policy FAIL 正例授权）可一并评估。
- 可观测：falco 参考运行 web-falco-gf2-pos2 的 Loki 直查与 Grafana 回查均 matched=1 且一致（阶段 3 矩阵）；仅 Web 视图一格 NOT_VISIBLE。
