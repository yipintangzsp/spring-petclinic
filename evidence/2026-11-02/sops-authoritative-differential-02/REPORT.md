SOPS_COMPATIBILITY = VERIFIED

范围：隔离 kind 中 12 项 REAL_CONTROLLED_EXECUTION；不是生产事故历史，也不代表整个 Policy Engine 已通过。

1. **refreshed token identity/lifetime**：system:serviceaccount:devsecops-system:security-fixture-executor；相同 SA UID；3600s；2026-11-02 16:14:44 +08:00 → 2026-11-02 17:14:44 +08:00；清理后已失效
2. **real SA authentication result**：PASS：host guard 与真实 Linux MIN_RBAC guard 均严格 TLS / CA / namespace UID / SelfSubjectReview 验证，无 admin fallback
3. **27/27 authorization recheck**：PASS；RBAC_DENIED 恢复后再验 27/27 PASS
4. **guard sanity result**：5/5 PASS（sanity 是单元检查；真实认证另有独立证据）
5. **authoritative baseline precheck**：MATCHED：23 个原 UID/完整 snapshot SHA、加密文件、工具及冻结源码匹配；仅预期 token 轮换
6. **total approved scenarios**：12
7. **applicable scenarios**：12
8. **NOT_APPLICABLE scenarios**：0；Secret type 的比较由 secrets-gate.mjs:21 明确执行
9. **old Gate executions**：12；冻结 Gate 源文件未修改；观察器透传真实调用、参数、stdin 和结果
10. **adapter/Policy executions**：12；existing SOPS adapter + baseline-v1 / standard
11. **oldDecision distribution**：PASS=1；FAIL=11
12. **policyDecision distribution**：PASS=1；FAIL=11
13. **total MATCH**：12
14. **total DRIFT**：0
15. **POSITIVE_FULL_PATH result**：PASS = PASS；4 个 Secret 的真实 decrypt/read/apply/read、UID/值保留及 13 项 Gate RBAC 检查通过
16. **WRONG_AGE_KEY result**：FAIL = FAIL；真实 SOPS exit=128；stdout=0 bytes；无 fallback key
17. **DECRYPT_ERROR result**：FAIL = FAIL；单字符密文破坏；真实 SOPS exit=25；stdout=0 bytes；与 wrong-key 区分
18. **SECRET_MISSING result**：FAIL = FAIL；真实 Secret 删除/读取失败；按新 UID 重建并留恢复收据
19. **SECRET_TYPE_MISMATCH result**：FAIL = FAIL；真实类型改为 basic-auth；冻结 Gate 的 data/type 比较拒绝
20. **SECRET_DATA_MISMATCH result**：FAIL = FAIL；真实 synthetic 值变更；仅归档 before/after 指纹
21. **UID_CONTINUITY_FAILURE result**：FAIL = FAIL；真实 apply 后删除/重建；实际 UID 不同而值指纹相同
22. **VALUE_PRESERVATION_FAILURE result**：FAIL = FAIL；真实 apply 后改值；实际 UID 相同而值指纹不同
23. **LEASE_HOLDER_MISMATCH result**：FAIL = FAIL；真实 Lease holder 不匹配；随后恢复原 spec
24. **RBAC_DENIED result**：FAIL = FAIL；仅从测试 reconciler Role 移除 get；真实受限凭据读取失败；恢复规则与 27 项授权
25. **TOOL_MISSING result**：FAIL = FAIL；仅临时 executor 缺 SOPS；真实 ENOENT；全局工具未改
26. **REPORT_WRITE_FAILURE result**：FAIL = FAIL；临时输出位置为目录；真实 EISDIR；未改生产目录权限
27. **raw-fact preservation result**：PASS；每例 evaluate 前后原始内存事实相同；证据含输出字节数/SHA、UID/值指纹、exit/signal/timeout；无新增 severity
28. **restoration/contamination result**：PASS：每例 23 对象语义和所需当前 UID 均核验；原 petclinic-db UID 经 4 次预期替换，原 baseline 未覆盖；不宣称 UID/字节完全恢复
29. **evidence-index validation**：PASS；precleanup 与 final 索引逐文件存在性/SHA 验证；matrix/cleanup 请求计数分开版本化
30. **fixture cleanup**：COMPLETE：23 个受控对象删除、两个 age 私钥及 token/kubeconfig 删除、临时 executor/私有目录无残留；旧 token HTTP 401；kind 保留
31. **production API access count**：0
32. **production Secret/credential reads**：0
33. **production age-key reads**：0
34. **production files modified YES/NO**：NO；4113 个既存项目文件 SHA 均保持一致
35. **Gate modified YES/NO**：NO；scanner-runtime、adapter 同样未改
36. **Policy baseline modified YES/NO**：NO
37. **Summary modified YES/NO**：NO
38. **SOPS_COMPATIBILITY**：VERIFIED — 仅本轮批准的冻结生产逻辑受控执行兼容性范围
39. **exact first drift/blocker if not VERIFIED**：无语义 drift 或剩余 blocker。执行前曾遇基础镜像默认 init 入口错误，显式指定 Python 后完成；未修改 Gate/adapter/Policy
40. **exact next permitted action if VERIFIED**：STOP。供下一轮复核全生产 Gate coverage；本轮不接 Summary、不启动统一插件契约或其他来源

证据入口：compatibility-verdict.json、precleanup-acceptance.json、final-evidence-index.json、final-index-validation.json。

事实与差分：每例 *-execution.json；恢复：每例 *-restoration-receipt.json；原基线：../sops-authoritative-baseline-02/authoritative-baseline.json（原始内容保留）。

观察边界：不把期望判定写入 raw fact；Node preload 仅透传观测与受控竞态屏障。decrypted stdout/data 仅在内存中传给原 Gate 与 adapter，归档只保留指纹/相等性；不归档 stderr 内容。初次入口错误保留于 pre-execution-entrypoint-error.json。

审计注：cleanup 与 matrix 复用了管理脚本的 request-count 文件名，已将 cleanup 计数另存；matrix snapshot 以原索引 SHA 逐字节核对恢复，详见 request-counter-version-receipt.json。未修改任何 Gate 决策证据。
