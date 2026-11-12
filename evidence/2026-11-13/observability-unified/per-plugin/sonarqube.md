# SonarQube — W12 结论
- G-S2 关闭（阶段 1）：Grafana 代理回查 clean/violating 均 matched=1、eventIdentity 与 Loki query-proof 一致 → OBSERVABILITY 升 VERIFIED。提交 f9022bc9（evidence，sonarqube-v2 目录新增 grafana-supplement-w12.json 等 4 文件）。
- MANAGEMENT: PARTIAL -> VERIFIED（G-S1 关闭）。view 接线（actions/app/controls）+ loki.mjs 白名单 sonarqube token 提交 699c4c87。
- 复验：view-driver 全 PASS（clean web-2bfea211 PASS/gate OK；finding web-0be38782 FAIL/gate ERROR；关态零执行；恢复 READY；Loki DELIVERED/VERIFIED）。单测 9/9。
- 注：capability projects 按案数排序，petclinic（双案）为 UI 默认项目；cleanroom 仅 clean 案。负例每轮新建 smv2-gatelab-* 项目的累积问题仍是 G-S4（未变）。
