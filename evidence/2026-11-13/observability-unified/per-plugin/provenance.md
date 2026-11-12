# Provenance — W12 结论
- MANAGEMENT: PARTIAL -> VERIFIED（G-P1 关闭，G-P2 接线提交一并完成）。提交 35eefaa2。
- 复验：view-driver 全 PASS（verified web-de4d4f38 PASS/historical-candidate；rejected web-f307a117 FAIL/wrong-digest；关态零执行；恢复 READY；Loki DELIVERED/VERIFIED）。单测 9/9。
- 口径：UiCase 场景词 verified/rejected，capability 对该插件只暴露这两场景，validateRequest 按插件强制；执行为本地离线 DSSE 验签（executionHost=local/offline），无 SSH/武装文件。
