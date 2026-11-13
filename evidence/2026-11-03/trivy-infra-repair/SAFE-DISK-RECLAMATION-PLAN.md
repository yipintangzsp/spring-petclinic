# Trivy 基础设施：安全回收计划及60项报告

结论：NOT_READY。按用户PART11停止在任何删除/代理修改之前。此报告不宣称已经完成空间回收，也不宣称已完整解析全部外部镜像引用。

## 安全回收计划（未执行）

| candidate | path/object | size GiB | class | safe_delete | expected GiB |
|---|---|---:|---|---|---:|
| 临时目录 | /tmp | 0.0001 | D | NO | 0 |
| 其他临时目录 | /var/tmp | 0.0347 | D | NO | 0 |
| Docker BuildKit cache | Docker daemon: 22 cache entries | 1.0869 | B | NO | 0 |
| 停止的SBOM验证容器 | runtime-sbom-build-9lbr9g-postgres-1 | 0.0000 | D | NO | 0 |
| Jenkins工作目录 | jenkins-pvc/workspace | 1.3399 | D | NO | 0 |
| Jenkins基线与审计快照 | jenkins-pvc/petclinic-platform-20261011/baseline | 1.2164 | C | NO | 0 |
| Jenkins归档 | jenkins-pvc/jobs | 1.0125 | C | NO | 0 |
| 系统/容器日志 | /var/log | 2.2299 | D | NO | 0 |
| Maven依赖缓存 | /home/zhang/.m2/repository + jenkins-pvc/.m2/repository | 0.5261 | D | NO | 0 |
| Sonar scanner缓存 | /home/zhang/.sonar/cache + jenkins-pvc/.sonar/cache | 0.7952 | D | NO | 0 |
| 现有本地registry | /home/zhang/devops-stack/ops-managed/registry-data | 40.0679 | C | NO | 0 |
| Harbor registry PVC | harbor-registry PVC | 16.8771 | C | NO | 0 |
| Harbor数据库PVC | database-data-harbor-database-0 PVC | 9.0444 | C | NO | 0 |
| Trivy cache | data-harbor-trivy-0 PVC | 3.0212 | C | NO | 0 |
| K3s恢复资产 | /opt/k3s-backup | 2.4114 | C | NO | 0 |
| CRI镜像 | 113 CRI image records | 不可简单相加 | B/C/D | NO | 0 |

完整每项reference proof、rollback impact、reproducibility、cleanup/recovery method见safe-reclamation-plan.json。没有安全删除命令可执行；不能先删除不足量的小候选再寻找风险更高目标。

## 验收报告

1. **pressured filesystem**：/dev/vda2, ext4, mounted /；nodefs/imagefs为该文件系统。

2. **before total/used/available**：251.86 / 196.16 / 43.42 GiB。

3. **inode status**：16,842,752 total，1,520,390 used，约10%；不是inode耗尽。

4. **required available threshold**：49.78 GiB = 15% capacity + 12GiB；原值不变。

5. **shortfall**：最末采样缺6.39 GiB至guard，缺8.61 GiB至52GiB目标。

6. **image count**：CRI113；另Docker27，均保留；不将共享layers size相加当作reclaim。

7. **current production image identity**：sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137，Harbor GET200。

8. **rollback images retained**：立即前序RS revision163=83c2ae…（ci-218）、文档#214=a8c03e…均GET200；所有现存RS/离线依赖保留，candidate2fba…GET200。

9. **safe ephemeral reclaim candidates**：/tmp94,208B、/var/tmp37,273,600B；无逐文件ownership/过期/归档证明，不能直接删除。

10. **build-cache candidates**：Docker22 entries共约1.167GB，仅报告512.9MB reclaimable且部分shared；具体owner/重建证明不足，未prune。

11. **log candidates**：/var/log约2.23GiB，含当前incident/journal/pod日志；没有证明可删除的已归档过期集合。

12. **image candidates**：113逐image引用图：82强引用保留C，31外部证明不完整D；全部safe_delete=false。

13. **UNKNOWN candidates retained**：31镜像及未知workspaces/cache/log/volume均保留。图的外部缺口显式标注；没有宣称完整引用图通过。

14. **expected safe reclaim**：0已证明可安全执行的bytes；512.9MB只是未批准的cache上界，远不足目标。

15. **actual reclaimed**：0；没有任何delete/truncate/prune/GC。

16. **after available space**：43.39 GiB；自然变化不计入cleanup收益。

17. **disk guard PASS/FAIL**：FAIL；按PART11停止。

18. **Harbor health after cleanup**：未清理；只读健康复核7个Pod Ready，四个需保留artifact GET200。

19. **Jenkins health after cleanup**：未清理；petclinic-ci #270 SUCCESS，validation #30 SUCCESS且未运行。

20. **node health after cleanup**：未清理；三个node Ready，MemoryPressure等见nodes.stdout。

21. **PetClinic health after cleanup**：未清理；3/3Ready，generation175/revision164保持，HTTP200。

22. **xray before-listener**：127.0.0.1:10808，mixed/noauth；配置hash见local-baseline.json，不输出认证/出口内容。

23. **Harbor-required proxy address**：http://192.168.1.238:10808。

24. **before proxy connectivity**：Mac loopback到GHCR=401 challenge（连通）；Mac LAN curl exit7；Harbor container wget connection refused。

25. **selected proxy fix**：尚未选择实施；候选B是特定LAN地址上的独立可撤销forward，必须先证明来源ACL；不直接开启noauth全LAN代理。因PART11 STOP未进入修改。

26. **exact bind scope**：实际仍127.0.0.1:10808；没有新增listener。候选仅192.168.1.238:10808，禁止0.0.0.0。

27. **firewall/exposure result**：无新增暴露。forward来源ACL/firewall/WAN验证尚未执行，不能宣称修复后安全验证通过。

28. **proxy rollback**：本轮未改配置/未创建forward，无需恢复。未来B方案须先记录专属PID/nonce，撤销只能终止该PID并验证LAN listener消失、loopback保持；源配置不应被触碰。

29. **after TCP connectivity**：NOT_EXECUTED；没有proxy修改。

30. **after actual upstream connectivity**：NOT_EXECUTED；当前LAN路径仍拒绝连接。

31. **Trivy DB source**：保留原ghcr.io/aquasecurity/trivy-db:2、trivy-java-db:1及原refresh脚本的经官方manifest校验路径。无替代下载。

32. **DB refresh result**：NOT_EXECUTED，本轮磁盘前置保护未满足。

33. **DB version/timestamp**：原db Version2、java-db Version1，NextUpdate均2026-10-31，已过期；metadata.stdout原样保留。

34. **DB checksum/identity**：本轮未下载/替换DB，无新checksum；不得凭历史manifest宣称本轮fresh。

35. **DB refresh failure classification if any**：BLOCKED_DISK_PREREQUISITE；既有proxy TCP refusal也未修复。本轮不是download/parse失败。

36. **Trivy validation identity if reached**：未达到阶段21，不创建新robot/SA/token。

37. **Trivy candidate digest if reached**：未执行；保留既有2fbaea65…候选GET200，不对其触发扫描。

38. **Trivy runtime result if reached**：NOT_EXECUTED，不复用旧#23FAIL当本轮结果。

39. **Trivy Policy evaluation count**：本轮Trivy=0；只运行原单元/契约测试。

40. **Trivy Gate digest reuse**：NOT_EXECUTED，无新Trivy结果。

41. **files/images deleted**：空集合。

42. **evidence retained**：当前/历史REPORT、receipts、hash manifests、snapshots全部保留；本轮新增清单/保守引用图/健康及测试证据。

43. **unintended deletions**：0；无删除命令。

44. **production image retained YES/NO**：YES，Harbor GET200及现PodReady。

45. **rollback image retained YES/NO**：YES，即时前序163、文档#214及原RS镜像均未删除；前三个指定Harbor对象与candidate均200。

46. **production V1 state**：V1 active；Summary hash ec9ee51a…不变，455冻结Gate source引用哈希保持，2202 count不变。

47. **production Jenkins state**：仍#270 SUCCESS；专用validation仍#30 SUCCESS，无新build。

48. **release count**：0。

49. **rollout count**：0。

50. **DISK_RECLAMATION_READINESS**：NOT_READY

51. **DISK_RECLAMATION_EXECUTION**：INCOMPLETE

52. **PROXY_REACHABILITY**：INCOMPLETE

53. **TRIVY_DB_REFRESH**：INCOMPLETE

54. **TRIVY_RUNTIME_FACT_CAPTURE**：INCOMPLETE

55. **REAL_RUNTIME_FACT_CAPTURE**：INCOMPLETE

56. **REAL_POLICY_OWNER**：INCOMPLETE

57. **IMMUTABLE_ARTIFACT_RUNTIME**：INCOMPLETE

58. **SUMMARY_V2_MIGRATION**：INCOMPLETE

59. **exact blocker if incomplete**：已证明的安全候选不足以恢复至少52GiB；31镜像及外部tag/GitOps/Helm/Compose引用仍未知，不能以未运行作删除依据。最大43GB目录是registry，禁止手动删除；其他大项是业务/PVC/恢复资产。

60. **exact next permitted action**：先只读补齐外部引用和registry生命周期/存储扩容的具体影响方案。若发现可证明且足量的A/B候选，重新出dry-run计划；若需GC/扩容另明确范围与回滚。现在按PART11 STOP，不改proxy、不刷新DB、不继续Cosign/Dojo。

## 测试

- collector/owner/runtime：154/154 PASS。
- Policy core：5/5 PASS。
- contract：10/10 PASS。
- Regression：147/147 PASS（首次受沙箱临时回环监听限制，授权后原测试通过；未改测试）。
- 7项回收安全断言PASS；113镜像全部保留，外部引用缺口未被伪造成通过。
- 实际cleanup/proxy-after/DB-refresh/Trivy-runtime：NOT_EXECUTED。

```text
DISK_RECLAMATION_READINESS = NOT_READY
DISK_RECLAMATION_EXECUTION = INCOMPLETE
PROXY_REACHABILITY = INCOMPLETE
TRIVY_DB_REFRESH = INCOMPLETE
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```

STOP。
