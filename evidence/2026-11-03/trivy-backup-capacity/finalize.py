from pathlib import Path
import hashlib,json,re,sys
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];G=1024**3
read=lambda n:json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def gib(x):return f'{x/G:.2f} GiB'
# Frozen source and sealed evidence are read-only inputs.
refs=json.loads((R/'evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json').read_text())['checks']
checks=[{'path':x['path'],'expected':x['expected'],'actual':sha(R/x['path'])} for x in refs]
assert all(x['expected']==x['actual'] for x in checks)
seals=[]
for n in ('runtime-final-three','trivy-infra-repair','trivy-storage-expansion','trivy-pre-expansion'):
 p=O.parent/n;d=json.loads((p/'evidence-sha256.json').read_text());rows=[sha(p/k)==v for k,v in d['files'].items()];assert all(rows)
 seals.append({'directory':str(p.relative_to(R)),'filesChecked':len(rows),'indexSha256':sha(p/'evidence-sha256.json'),'allMatch':True})
save('source-preservation.json',{'checks':checks,'checkCount':len(checks),'uniquePaths':len(set(x['path'] for x in checks)),'allMatch':True,'priorSeals':seals,'compatibilityBaseline':2202,'compatibilityBaselineChanged':False,'productionCodeChanges':0,'head':'741ea2866ea142b24c7838e1ef25c8327c79d279'})
# Require exact suite coverage; keep the earlier 39-test subset separate and do not count it twice.
suites=[]
for n,total in [('runtime-tests.log',154),('regression-tests.log',147),('policy-core-tests.log',5)]:
 s=(O/n).read_text();assert re.search(rf'ℹ tests {total}\b',s) and re.search(rf'ℹ pass {total}\b',s) and 'ℹ fail 0' in s
 suites.append({'suite':n,'pass':total,'fail':0,'evidenceClass':'LOCAL_TESTS_NOT_PRODUCTION_EXECUTION'})
for n,total in [('cleanup-destination-tests.log',24),('expansion-guard-tests.log',30)]:
 s=(O/n).read_text();assert f'Ran {total} tests' in s and s.strip().endswith('OK');suites.append({'suite':n,'pass':total,'fail':0,'evidenceClass':'PURE_GUARD_UNIT_TESTS_SYNTHETIC_POSITIVES_ONLY'})
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
suites.append({'suite':'policy-contract.json','pass':10,'fail':0})
assert read('restore-plan-tests.json')['pass']==17 and read('restore-plan-tests.json')['fail']==0
save('test-results.json',{'suites':suites,'restorePlanAssertions':17,'actualBackupValidationChecks':'NOT_EXECUTED_NO_BACKUP','actualDestinationTest':'NOT_EXECUTED_NO_ACCEPTED_TARGET','compatibilityBaseline':2202,'compatibilityBaselineChanged':False,'realVmRestoreExecuted':False,'productionPipelineTriggered':False})
vm=read('vm-identity.json');cap=read('capacity-model.json');post=read('host-after-audit.json');plan=read('host-reclamation-plan.json');models=read('backup-representation-models.json');dest=read('destination-inventory.json');v=read('verdict.json');health=read('health-final.json');nodes=read('node-lease-postflight.json')['nodes'];registry=read('registry-retention-final.json');jenkins=read('live-jenkins-final.json');job=next(j for j in jenkins['jobs'] if j['job']=='petclinic-ci')
assert job['latestBuild']==270 and job['result']=='SUCCESS' and not job['building'] and job['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
assert health['deployment']['generation']==175 and health['deployment']['revision']=='164' and health['deployment']['ready']==3 and health['http']['status']=='200' and all(x['ready'] for x in health['harborPods'])
assert len(nodes)==3 and all(any(c['type']=='Ready' and c['status']=='True' for c in x['conditions']) for x in nodes)
assert len(registry['artifacts'])==4 and all(x['httpStatus']==200 for x in registry['artifacts'])
assert not plan['executionAllowed'] and not plan['actualDeletedHostPaths'] and models['backupCreated'] is False
cap.update({'hostFreeAfterAudit':post['HOST_FREE_AUTHORITATIVE'],'currentRemainingGapTo37GiB':max(0,37*G-post['HOST_FREE_AUTHORITATIVE']),'noCleanupDeltaAttribution':True});save('capacity-model.json',cap)
rows=[
('backup destination inventory','16个实际候选记录：11个宿主挂载、3个现有节点root、2个File Provider路径。无外置磁盘/USB存储、SMB共享或NFS挂载。现有SSH配置未识别其他独立备份服务器；不扫描、不索取新权限。逐项见destination-inventory.json。'),
('selected backup destination','NONE；未接受任何目标。'),
('destination filesystem','无选定目标。内部APFS共享container，伪FS不能存储备份；云端同步目录不是已验证独立挂载；remote node fs仅有容量stats，未验证格式/文件能力。'),
('destination free space','无选定目标。宿主before '+gib(cap['hostFreeBeforeCleanup'])+'；aliyun root约9.43GiB、ucloud约52.83GiB，不足本轮观测205GiB数据/完整复制方案。压缩可否适配未证实，不能以推定压缩比接受。devops root是源VM自身。'),
('destination suitability','全部NO。没有目标具备空间、稳定挂载、大文件/稀疏往返、独立恢复读取和完整窗口可用证明。云同步完成/限额/离线恢复均未知；不把可写当适合。'),
('BACKUP_DESTINATION_READINESS',v['BACKUP_DESTINATION_READINESS']),
('host free before cleanup',gib(cap['hostFreeBeforeCleanup'])+f"（{cap['hostFreeBeforeCleanup']} bytes），APFS+df取较小值；purgeable不计。"),
('host safe reclaim candidates','44项候选带path/size/owner/tool/last-use/reproducibility/current FD/project dependency/recovery/safe_delete证据。正容量候选均REVIEW_REQUIRED/RETAIN/UNKNOWN；Homebrew和Gradle为空，无可回收量。tier顺序明确，Tier4不执行。'),
('safe reclaim total','SAFE_RECLAIM_TOTAL=0。Chrome/CloudKit/当前Codex日志不能按缓存名删除；Colima default停止不等于可丢弃；Documents内镜像、cache checkpoint、CI205/206归档为离线/回滚保留。22个归档均无重复/可丢弃证明。'),
('actual deleted host paths','[]；未执行任何宿主用户文件删除，也未docker prune、colima delete、清空Trash或删镜像。'),
('actual reclaimed space','0 bytes；free自然波动不记为清理收益。'),
('host free after cleanup','未cleanup，audit后复测 '+gib(post['HOST_FREE_AUTHORITATIVE'])+f"（{post['HOST_FREE_AUTHORITATIVE']} bytes）。仍比37GiB低约{(37*G-post['HOST_FREE_AUTHORITATIVE'])/G:.2f}GiB；preferred45–50GiB需更多。"),
('HOST_CAPACITY_READINESS',v['HOST_CAPACITY_READINESS']+'；独立备份条件下+16预算37GiB（growth16+metadata1+temp4+hostreserve16），+32需53GiB；本地完整备份还另加约342.69GiB。'),
('HOST_RECLAMATION_EXECUTION',v['HOST_RECLAMATION_EXECUTION']+'；安全集不足则STOP在删除前，未将0次删除称为执行成功。'),
('selected backup format',models['BACKUP_FORMAT_SELECTED']+'。A完整bundle、B盘+全部config/EFI、C稀疏、D无损压缩、Eclone/snapshot的logical/allocated/temp/metadata/空间/时长与依赖见backup-representation-models.json。'),
('backup consistency model','计划clean shutdown后的完整静态bundle，不接受live copy。保守上限约342.69GiB；当前allocated约205.01GiB，若冷源/目标稀疏与恢复实证成立，可能采用约207.01GiB预算，尚未验证。压缩比/实际传输速度/停机时长未实测。'),
('source VM shutdown required','YES，冷备份需要。实际shutdown=0，因为目标和容量前提未通过；不是缺少用户重复授权。'),
('image-released proof','未取得：VM仍Running，当前QEMULauncher PID18121 / FD18 read-write。guard明确拒绝。source SEEK_DATA/HOLE只读普查133054区间完成，但期间mtime变化，不能当静止源/冷备证据。'),
('backup command/tool','未执行。拟用现有rsync -aS --extended-attributes SOURCE_BUNDLE/ PRECREATED_EMPTY_BACKUP_BUNDLE/；具体目标先验证。无--delete、无转换、无网络下载依赖。'),
('backup bytes written','0；本目录日志/报告写入不是backup bytes。'),
('backup path','NONE；原bundle路径固定于RESTORE-AND-COLD-BACKUP-PLAN.md，不虚构备份目录。'),
('backup validation checks','Backup exists=false；源停机/释放未成立；size/structure/config/hash/offline info/check=NOT_TESTED。尚无可检查备份，所以不执行qemu-img check；活动源仅info/OS extent metadata。'),
('BACKUP_VALIDATION',v['BACKUP_VALIDATION']),
('restore procedure','精确原路径、UUID、config/EFI绑定已记录；停止并无FD→有容量时保留坏副本→备份hash→恢复完整bundle→UTM附加/boot→hostname/root/kernel/network/k3s/Jenkins/Harbor/PetClinic/digest验收。不能覆盖当前VM做恢复实验。详见计划。'),
('restore validation method','17项文档/guard断言通过，仅验证计划结构。当前无备份，OFFLINE_IMAGE_VALIDATED也未执行；隔离boot须全断网、新UUID/MAC、无共享生产写路径/卷，另需资源。原22+clone22+Colima2GiB超过32GiB宿主，不能并发尝试。'),
('RESTORE_VALIDATION_LEVEL',v['RESTORE_VALIDATION_LEVEL']),
('RESTORE_READINESS',v['RESTORE_READINESS']+'；无可用备份及恢复暂存/验证，精确文档本身不代表恢复成功。'),
('original VM restart result','NOT_REQUIRED_NOT_EXECUTED；原VM未关闭，仍持原UUID运行，config SHA3b10a9eb797dd8bad070a9b77f0f0d381303c7b4b20d2b1658f623371dcc1baf与前轮相同；无“重启即修复”结论。'),
('Jenkins health','petclinic-ci #270 SUCCESS，building=false；validation #30 SUCCESS，所有API列出的build均idle。V1 summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变；未触发新build。'),
('Harbor health','7/7 Pod Ready；只读GC历史均完成，replication为空；没有启动GC。Docker system df报告security-test Build Cache=0；单独builder du在已安装客户端不支持，未安装/修改工具。'),
('protected digests','4/4 GET200，完整digest见registry-retention-final.json；current489cb821…、previous83c2ae78…、known-good#214 a8c03e46…、candidate2fbaea65…及其他保留依赖均未删除。'),
('K3s health','当前采样devops/aliyun-worker/ucloud-worker均Ready，MemoryPressure/DiskPressure/PIDPressure=false；未重启/改配置。此为本轮健康快照，不宣称永久稳定性。'),
('PetClinic health','3/3 Ready，UID/generation175/revision164与基线一致；保留Deployment/RS及业务数据，未改发布逻辑。'),
('HTTP 200','YES；通过原Service clusterIP在现有节点实测HTTP200。'),
('VM_MAINTENANCE_READINESS',v['VM_MAINTENANCE_READINESS']+'；OFFLINE_EXPANSION_REQUIRED方案保留，无排它窗口、合适目标、容量与可恢复备份，不停机。'),
('BACKING_DISK_RESIZE_READINESS',v['BACKING_DISK_RESIZE_READINESS']+'；无备份/恢复依赖。即便将来READY，本轮仍明确禁止resize。'),
('GUEST_PARTITION_GROW_READINESS',v['GUEST_PARTITION_GROW_READINESS']+'仅指上一轮绑定几何与工具的步骤就绪；不是执行授权，当前parent仍258GiB无尾部空间。'),
('FILESYSTEM_GROW_READINESS',v['FILESYSTEM_GROW_READINESS']+'仅指ext4/resize2fs步骤匹配。当前全局门禁未过，执行0。'),
('STORAGE_EXPANSION_READINESS',v['STORAGE_EXPANSION_READINESS']),
('disk resize count','0；guest partition grow=0；filesystem grow=0。'),
('proxy modification count','0'),
('Trivy DB refresh count','0；Trivy runtime scan=0。'),
('Harbor image deletion count','0；containerd镜像删除=0；HarborGC执行=0。'),
('release count','0'),
('rollout count','0'),
('exact blocker if still NOT_READY','BACKUP_DESTINATION_READINESS=NOT_READY：无稳定、独立且已验证容量/大文件恢复的目标；HOST_CAPACITY_READINESS=NOT_READY：当前free约25.21GiB，缺约11.79GiB，SAFE_RECLAIM_TOTAL=0。因此备份/恢复未验证，维护和扩盘不能通过。'),
('exact next permitted action if STORAGE_EXPANSION_READINESS = READY','当前未READY：先提供可合法使用的独立目标/已有存储挂载入口，并为至少约11.79GiB宿主清理量补精确可丢弃证明；可验证冷源与目标稀疏恢复以实证重算207GiB级预算，不用假设压缩比。若将来全部READY，唯一下一动作仍是报告并STOP；扩盘是下一轮独立变更，本轮不得执行，也不进入proxy/DB/Cosign/Dojo。'),
]
assert len(rows)==47
head='# 备份目标与宿主空间收口：47项验收\n\n本轮只做实际存储/清理证据调查、纯防护测试及只读平台验收；capability保持13/16，compatibility2202未提升。读数有时间波动，执行前必须重新实测。无生产写入、无用户文件删除、无冷备份、无扩盘。\n\n'
body='\n\n'.join(f'{i}. **{k}**：{text}' for i,(k,text) in enumerate(rows,1))
footer='\n\n## Final verdicts\n\n```json\n'+json.dumps(v,indent=2)+'\n```\n\n验证：Runtime154/154、Regression147/147、Policy core5/5、contract10/10、原pre-expansion guards30/30、新cleanup/destination guards24/24、restore-plan结构断言17项。后面三类是synthetic/文档防护验证，不能冒充真实备份/恢复。455个冻结引用（229唯一源码）及120/72/43/97文件先前seal均不变。\n\nSTOP：无足量safe deletion set，按条件停止在任何删除和关机前；不承诺依赖目前不存在的备份目标。\n'
(O/'REPORT-47.md').write_text(head+body+footer)
print(json.dumps({'reportItems':len(rows),'hostFreeBeforeGiB':cap['hostFreeBeforeCleanup']/G,'hostFreeAfterAuditGiB':post['HOST_FREE_AUTHORITATIVE']/G,'safeReclaimBytes':0,'sourceRefs':len(checks),'priorSealedCounts':[s['filesChecked'] for s in seals],'verdict':v},ensure_ascii=False))
