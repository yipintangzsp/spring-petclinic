# Trivy：扩容可行性与UNKNOWN回退取证（62项报告）

结论：STORAGE_EXPANSION_READINESS=NOT_READY；按附件转入fallback，31个旧UNKNOWN中30个取得真实正引用，1个保留UNKNOWN，SAFE_DELETE=0。无磁盘/分区/文件系统/镜像/代理修改。

## 容量和恢复判断

- 客体磁盘258GiB；root已到最后可用扇区，不能跳过backing扩容直接grow。
- host APFS可用约25.25GiB；qcow2逻辑增长不立即分配同量host空间，但后续DB/registry写入及snapshot COW必须预算。
- 最小建议+16GiB，推荐+32GiB；这些是条件性建议，非已具备可执行READY。
- 当前UTM4.7.5；尚无验证过的live resize入口和pre-change一致性恢复点。

## 62项结果

1. **backing storage type**：Mac APFS上的UTM QEMU qcow2；devops.utm唯一可写VirtIO Disk。UTM4.7.5，QEMULauncher PID18121实际持有该镜像。

2. **disk current size**：客体/QCOW2 virtual-size=258GiB；镜像文件length=340.69GiB、已分配=204.93GiB。file length不是客体容量，也不是尾部可用分区空间。

3. **partition layout**：GPT；vda1 EFI 2048–2203647；vda2 Linux 2203648–541065182；最后可用扇区541065182。

4. **filesystem type**：ext4，root=/dev/vda2；无LVM、无活动mdraid。

5. **free unpartitioned space**：可供vda2尾部增长的空间=0；GPT尾部保留扇区不能算可扩空间。

6. **online grow capability**：ext4条件性支持online grow；growpart/resize2fs已安装。不能据此假设host backing可以安全在线增大；未验证支持的live管理接口。

7. **snapshot capability**：QCOW2格式具备snapshot能力；已安装UTM4.7.5的可用一致性快照/恢复管理路径尚未验证。没有创建新snapshot；当前在线文档不可直接当作已安装版本保证。

8. **expansion rollback capability**：需要经过验证的一致性VM snapshot/backup并能恢复VM及所有相关驱动。宿主当前空间不足以保留独立完整镜像副本；APFS clone/内部snapshot若采用，仍须预算COW并验证一致性，不能声称已具备回滚。禁止用在线缩分区/ext4回滚。

9. **current available**：最新guest 43.52GiB；host APFS 25.25GiB。自然波动不算本轮回收。

10. **required minimum**：原guard=49.78GiB，15%当前capacity+12GiB；扩容后仍按新capacity重新计算，禁止固定旧阈值冒充满足。

11. **preferred target**：至少52GiB，且必须满足扩容后重算guard，两者取更严。

12. **proposed minimum expansion**：建议最小+16GiB（258→274）；预计guest avail约58.28GiB、guard约52.11GiB，仅估算，未批准执行。考虑现有reserve/metadata，不只增加8.61GiB。

13. **proposed recommended expansion**：建议+32GiB（258→290）；预计avail约73.03GiB、guard约54.43GiB，为DB临时约4GiB、registry约8GiB、validation/container增长约4GiB保留预算。宿主物理写入/快照/COW预算必须先验证，不能只增虚拟数字。

14. **storage health**：tune2fs报告clean、inode约10%；24h内核查询无匹配I/O/EXT4/buffer/corruption错误。mounted journal needs_recovery不等同于已发现损坏；未运行离线全盘fsck。QCOW2 info是运行中只读header观察，不是完整一致性检查。

15. **expansion risk classification**：REQUIRES_SNAPSHOT_OR_CONSISTENT_BACKUP；支持的online backing入口/maintenance影响未解决；host容量及rollback预算未批准。不能归为已证明LOW_RISK_ONLINE。

16. **STORAGE_EXPANSION_READINESS**：NOT_READY。

17. **snapshot result if applicable**：NOT_CREATED。snapshot ID/time=null；没有验证过的pre-expansion恢复点。

18. **backing volume expansion result**：NOT_EXECUTED。没有修改正在使用的qcow2，也没有停VM。

19. **partition expansion result**：NOT_EXECUTED；vda2起点/type/EFI均未改。

20. **filesystem expansion result**：NOT_EXECUTED；未format/mkfs，也未改变reserved space。

21. **post-expansion available**：未扩容；当前仍约43.52GiB。

22. **STORAGE_EXPANSION_EXECUTION**：INCOMPLETE。

23. **UNKNOWN image count before analysis**：31。

24. **SAFE_DELETE count if fallback analysis used**：0；30重新判为REFERENCED，1仍UNKNOWN并保留。

25. **estimated actual registry reclaim**：已证明可回收=0；没有将virtual/压缩image size累加为真实可回收空间。

26. **images actually deleted**：0。

27. **DISK_RECLAMATION_READINESS**：NOT_READY。

28. **DISK_RECLAMATION_EXECUTION**：INCOMPLETE。

29. **xray before bind**：沿用已冻结、未修改的127.0.0.1:10808 mixed/noauth；本轮未进入proxy修改阶段。

30. **selected proxy fix**：NOT_SELECTED_FOR_EXECUTION。先满足storage guard；不能在磁盘失败时跳阶段开放LAN入口。

31. **xray after bind**：无变更；未创建转发listener或修改路由/防火墙。

32. **proxy exposure scope**：无新增暴露；未开展修复后来源ACL/WAN验证。

33. **actual caller connectivity**：当前已知Harbor→MacLAN10808仍未修复，本轮没有新proxy成功证明。

34. **upstream Trivy endpoint connectivity**：保留原前置证据；本轮未执行修复后manifest/blob成功验证。

35. **PROXY_REACHABILITY**：INCOMPLETE。

36. **DB refresh path**：原infra/observability/scanner-db-refresh.mjs冻结路径不变；storage guard不满足，未执行任何替代下载。

37. **DB identity/version**：本轮未生成新库。现有db Version2/java-db Version1证据保留，不把旧库当fresh。

38. **DB timestamp**：无新timestamp；未改NextUpdate/DownloadedAt。

39. **DB checksum**：无本轮新checksum。历史官方manifest不能替代本轮成功刷新。

40. **TRIVY_DB_REFRESH**：INCOMPLETE，BLOCKED_STORAGE。

41. **Trivy validation identity**：未新建；不能在DB未VERIFIED前进入阶段19。

42. **Trivy candidate digest**：既有2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55保留GET200，未触发扫描。

43. **Trivy scan/report result**：NOT_EXECUTED，不复用#23旧FAIL作本轮结果。

44. **Trivy Policy evaluation count**：0本轮runtime评价；单元测试独立标注。

45. **Trivy Gate digest reuse**：无新runtime receipt，NOT_EXECUTED。

46. **TRIVY_RUNTIME_FACT_CAPTURE**：INCOMPLETE。

47. **final wired capability count**：13/16；未满足Trivy VERIFIED，不能提升14/16。

48. **remaining runtime sources**：Trivy、Cosign、DefectDojo；后两者本轮未执行。

49. **protected image status**：当前489cb…、立即前序163=83c2…、文档#214=a8c03…、candidate2fba…均Harbor GET200，均保留。

50. **Harbor status**：7个Pod Ready、registry四个指定artifact可读；无tag/manifest/blob/GC变更。

51. **Jenkins status**：production #270 SUCCESS；validation仍#30 SUCCESS，无新构建。

52. **node status**：3个节点Ready，原heavy Lease已释放。

53. **PetClinic status**：3/3Ready，generation175/revision164保持；HTTP200。

54. **V1 status**：V1 active，Summary ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8不变；455个冻结source引用hash保持，2202 count不变。

55. **release count**：0。

56. **rollout count**：0。

57. **REAL_RUNTIME_FACT_CAPTURE**：INCOMPLETE。

58. **REAL_POLICY_OWNER**：INCOMPLETE。

59. **IMMUTABLE_ARTIFACT_RUNTIME**：INCOMPLETE。

60. **SUMMARY_V2_MIGRATION**：INCOMPLETE。

61. **exact blocker if incomplete**：无分区尾部空间；backing尚无安全online resize/一致性snapshot恢复证明。宿主只余约25GiB，必须先验证实际写入+COW+既有host保留余量，而非假定sparse扩容不会产生后续压力。fallback查明30个正引用，余1个UNKNOWN不可删除；SAFE_DELETE=0，无法恢复原guard。

62. **exact next permitted action**：准备宿主物理空间/外部备份目标与实际写入预算，核实支持的UTM4.7.5 online管理接口或安排可接受的VM维护窗口。形成一致性backup/snapshot与恢复步骤后重新判断READY；若READY，支持的backing增大→客体可见→growpart /dev/vda 2→resize2fs /dev/vda2，每步验证，不能倒序。保持UNKNOWN镜像，不执行GC；storage未满足前不改proxy/刷新DB。STOP。

## UNKNOWN逐镜像判定

| image/config id | verdict | 正引用证据数 | safe_delete |
|---|---|---:|---|
| sha256:1c7b793ecaa5d3f4000c816022d57c14e92fcd239022a20131807d9a61e9cb8b | REFERENCED | 2 | NO |
| sha256:0cb94100ffc5e7577c64e105b6d607aacd13dd90893f95741b1dabb4015af6f2 | REFERENCED | 1 | NO |
| sha256:5aa9ad6b2b430ad3eae27223fab0bd72a21f24d6c4238be96a0a1178f2da5b54 | REFERENCED | 1 | NO |
| sha256:12ff7da590f1712a5598c55cd668bd29e2dd2caa6bb6c68fd1e18bf15d8b8f3a | REFERENCED | 1 | NO |
| sha256:a6e9a665bc5a015180741588d80ebe28a40730e09904192094884924465f412b | REFERENCED | 1 | NO |
| sha256:9543efeebb580f1158303840f66539738ea762028fc9ca77cd00d000d9e2d44a | REFERENCED | 1 | NO |
| sha256:0cf94dfb05603268641e4ba838ff295bb0dc4b70f1bad993a894dc0a46db01a6 | REFERENCED | 2 | NO |
| sha256:8350a2319ae7a15e5e76ef790a10443ceb86229147b282989d38b6f3a82b0a26 | REFERENCED | 1 | NO |
| sha256:0698546a496e6b283d2c3fca1ff976d76f4807af5ad1f81274734e47a442d0a8 | REFERENCED | 1 | NO |
| sha256:51af20b832e103c5dee157df8ce9649fad228416c8600cbbdfd0866c6125e6f9 | REFERENCED | 1 | NO |
| sha256:3eb57bcf62ea25a775c56e6e4abd6c7d9bbbf360c2ef709db1532f464c16cf86 | REFERENCED | 1 | NO |
| sha256:0c3aeef526d77e3e7c0949b5389f2d18e75ae7911f25bbec49b31201fe89ca3a | REFERENCED | 1 | NO |
| sha256:6256c3d38f8dba50fec410116f13a3d1784f4f5ff0f2707ecba8a8bd5b2e1909 | REFERENCED | 1 | NO |
| sha256:1364c6d80c42426ed5b7fd4ed21d7dde6b834f97c827ba71add68cb7e17f786e | REFERENCED | 1 | NO |
| sha256:7d46a07936af93fcce097459055f93ab07331509aa55f4a2a90d95a3ace1850e | REFERENCED | 127 | NO |
| sha256:f721fb317e0abb97d0e2d5ce6d80295d76712aba4a7eeb8de9d29f1f25c61444 | REFERENCED | 1 | NO |
| sha256:bc6f168d68a5184f19517c3f1a01f7b86f7bd09a20a1d1f229cd96dd04686e58 | REFERENCED | 1 | NO |
| sha256:4ccc2d1ac990c4eb4eb94888e71088f04a192909ee9b963405ec91eac265f2f5 | REFERENCED | 1 | NO |
| sha256:50468b51a673c885591642d07275a3b88c6c8857c9c96d19ea249bbe0a9e5a37 | REFERENCED | 1 | NO |
| sha256:31fa24a9d9f03a52cb6714eb728ccd5581089339a619a543ca2ebd16e5684b66 | REFERENCED | 1 | NO |
| sha256:b1c7252d10412c5219fdbaf61a6dc3ec24a50456b7b52910b8ca4a7dca5436aa | REFERENCED | 1 | NO |
| sha256:4ed9b64e6cd7279c18aa0e21b229d9ee66fcc70d495bd7b376ef899c9195407e | REFERENCED | 1 | NO |
| sha256:74c38a41af3adfd3ed6c8a3add9ae88e8fb512eaa912f500f3dfd93a3c408ce9 | REFERENCED | 1 | NO |
| sha256:aa63eb5925b93422dffdfffa26953d9fc4a15d6dfe4a19cb6c2859a3d8ad7811 | REFERENCED | 1 | NO |
| sha256:9ec87d514285e0a2c4f64cd57e479c2459cb6a45174ff5b5f587269e6f14df4d | REFERENCED | 1 | NO |
| sha256:c265b6f0d4d869913bc1c4d3188b4046b029857454ac7a89fee2f83daa1e40fc | REFERENCED | 1 | NO |
| sha256:45dc594b16aadd645d27377f0a2ef1a832cf4fc509b0106d29f7c0e7a03bd5e8 | REFERENCED | 1 | NO |
| sha256:c014d4cf5d0ce1855df5a202835987c6d1f1364e449de36d89e412b3e918ca9b | REFERENCED | 1 | NO |
| sha256:87a8a5a0fe873ba136dfd4c583f321795525c987ca24d53b9182cd20274da9d6 | REFERENCED | 1 | NO |
| sha256:82c58a5c5b738fd9ffc8fe6bcc0a9467360abfab015b7ae70384563e895b68ff | UNKNOWN | 0 | NO |
| sha256:cdf1dc1cb14672bf5a4aa2697f711ad0ab7000d31187b7132560c8702f32808c | REFERENCED | 1 | NO |

完整Harbor tags/children、local OCI index/config/layer和配置/runtime匹配保留于unknown-image-verdicts.json；accessories=null不作为无referrers证明，历史/attestation反向图缺口不当作无引用。只判定保留，不授权清理。

## 测试

runtime 154/154，Regression 147/147，Policy core5/5，contract10/10均PASS。topology、保留镜像与当前健康检查通过；resize/proxy-after/DB/runtime真实执行均NOT_EXECUTED。

## 官方操作约束与适用范围

- [QEMU qemu-img](https://www.qemu.org/docs/master/tools/qemu-img.html)：不使用离线image修改工具更改运行中VM镜像。
- [UTM Resize](https://docs.getutm.app/settings-qemu/drive/resize-and-compress/)：逻辑resize不立即占用相同host空间，客体还需要增长文件系统；应先备份。
- [UTM Snapshots](https://docs.getutm.app/advanced/snapshots/)：当前在线文档不是已安装4.7.5支持情况的实际验证；未据此虚构snapshot能力/ID。

```text
STORAGE_EXPANSION_READINESS = NOT_READY
STORAGE_EXPANSION_EXECUTION = INCOMPLETE
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

STOP；不继续Cosign/Dojo/Summary V2。
