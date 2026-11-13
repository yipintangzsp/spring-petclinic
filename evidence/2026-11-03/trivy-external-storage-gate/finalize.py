from pathlib import Path
import json,hashlib,re,sys
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];P=O.parent/'trivy-backup-capacity';G=1024**3
read=lambda p:json.loads(p.read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
change=read(O/'material-change.json');v=read(O/'verdict.json');assert change['MATERIAL_STORAGE_CHANGE']=='NO' and change['hostShortfallBytes']>0
# Read source and seals only; do not re-open inventories of cleanup candidates or images.
index=read(P/'evidence-sha256.json');assert all(sha(P/k)==h for k,h in index['files'].items())
refs=read(R/'evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json')['checks']
checks=[{'path':x['path'],'expected':x['expected'],'actual':sha(R/x['path'])} for x in refs];assert all(x['expected']==x['actual'] for x in checks)
save('source-preservation.json',{'checks':checks,'allMatch':True,'count':len(checks),'uniquePaths':len(set(x['path'] for x in checks)),'previousSealFilesChecked':len(index['files']),'previousSealUnchanged':True,'previousSealIndexSha256':sha(P/'evidence-sha256.json'),'compatibilityBaseline':2202,'compatibilityBaselineChanged':False})
suites=[]
for n,total in [('runtime-tests.log',154),('regression-tests.log',147),('policy-core-tests.log',5)]:
 s=(O/n).read_text();assert re.search(rf'ℹ pass {total}\b',s) and 'ℹ fail 0' in s;suites.append({'suite':n,'pass':total,'fail':0})
for n,total in [('external-destination-guard-tests.log',24),('backup-image-guard-tests.log',30)]:
 s=(O/n).read_text();assert f'Ran {total} tests' in s and s.strip().endswith('OK');suites.append({'suite':n,'pass':total,'fail':0,'scope':'PURE_GUARDS_SYNTHETIC_INPUTS_NOT_REAL_STORAGE_ACCEPTANCE'})
assert read(O/'policy-contract.json')['ready'] and len(read(O/'policy-contract.json')['checks'])==10;suites.append({'suite':'contract','pass':10,'fail':0})
plan=(P/'RESTORE-AND-COLD-BACKUP-PLAN.md').read_text()
restoreChecks={
'exactOriginalBundle':'/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm' in plan,
'exactVmIdentity':'4C8DEDBC-D2FB-43F6-99EC-C2C6F9C1FF46' in plan,
'configAndEfiPreserved':'config.plist' in plan and 'Data/efi_vars.fd' in plan,
'coldSourceAndRelease':'QEMULauncher进程退出' in plan,
'isolatedNetworkDisabled':'禁用全部网络接口' in plan,
'productionWritesPrevented':'禁用共享宿主可写目录' in plan,
'neverOverwriteLiveForTest':'不得覆盖当前VM来测试恢复' in plan,
'bootResourceCheck':'宿主32GiB' in plan,
'noCopyAsRestoreClaim':'原VM正常重启不能当作备份恢复成功' in plan,
'noBackupNoValidation':'RESTORE_VALIDATION_LEVEL=NOT_VALIDATED' in plan,
'noResizeThisIteration':'resize/partition-grow/fs-grow均留到下一独立变更' in plan,
}
assert all(restoreChecks.values());save('restore-plan-tests.json',{'pass':len(restoreChecks),'fail':0,'checks':restoreChecks,'scope':'EXISTING_SEALED_PLAN_REVALIDATED_ONLY_NO_ACTUAL_RESTORE'})
save('test-results.json',{'suites':suites,'restorePlanAssertions':len(restoreChecks),'sparseCopyTests':'NOT_APPLICABLE_NO_NEW_DESTINATION','actualBackupValidation':'NOT_APPLICABLE_NO_BACKUP','productionPipelineStarted':False,'compatibilityBaseline':2202})
health=read(O/'health-final.json');job=read(O/'live-jenkins-final.json')['jobs'][0];reg=read(O/'registry-retention-final.json');nodes=read(O/'node-lease-postflight.json')['nodes']
assert job['job']=='petclinic-ci' and job['latestBuild']==270 and job['result']=='SUCCESS' and job['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
assert health['deployment']['generation']==175 and health['deployment']['revision']=='164' and health['deployment']['ready']==3 and health['http']['status']=='200' and all(p['ready'] for p in health['harborPods'])
assert len(nodes)==3 and all(any(c['type']=='Ready' and c['status']=='True' for c in n['conditions']) for n in nodes)
assert len(reg['artifacts'])==4 and all(x['httpStatus']==200 for x in reg['artifacts'])
models=read(P/'backup-representation-models.json');a=models['models'][0]
save('architecture-disposition.json',{'scope':'EARLY_STOP_NO_NEW_STORAGE_NO_DETAILED_CANDIDATE_VALIDATION_OR_BENCHMARK','optionA':{'activeVm':'Current internal bundle retained as authoritative','backupDestination':None,'externalRequiredBytesConservative':a['requiredDestinationFreeBytesConservative'],'hostRequiredBytes':37*G,'hostShortfallBytes':change['hostShortfallBytes'],'risk':'No independent backup, current host below guard','verdict':'BLOCKED'},'optionB':{'externalVmCandidate':None,'originalInternalCopy':'MUST_RETAIN_UNTOUCHED_NO_RECLAIM_ASSUMED','requiredExternalBytes':'Must fit cold copy plus future growth, metadata, operational/restore staging margin, based on target measurements','hostRequirement':'NOT_DERIVED_NO_TARGET_OR_SELECTED_MIGRATION_ARCHITECTURE; do not mechanically apply or lower 37GiB','independence':'External primary alone is not a backup; original internal or another independent validated backup must remain','risks':['Disconnect/power loss/performance/boot reliability unmeasured','Installed UTM external-storage compatibility and target sparse/large-file semantics not validated','Need CPU/RAM and all-network-off restore validation; no concurrent clone attempted'],'performance':'NOT_TESTED_NO_DEVICE','downtime':'NOT_ESTIMATED_NO_TARGET_THROUGHPUT','restoreComplexity':'NOT_VALIDATED','futureExpansion':'NOT_PROVEN','verdict':'BLOCKED'},'PREFERRED_STORAGE_ARCHITECTURE':v['PREFERRED_STORAGE_ARCHITECTURE'],'backupFormatPreferredWhenReady':models['BACKUP_FORMAT_SELECTED'],'storageClassRecommendation':'NOT_REACHED_EARLY_STOP; no marketing capacity recommendation or untested 207GiB acceptance','noShutdown':True,'noMigration':True,'noResize':True})
rows=[
('state changed since previous audit YES/NO','NO；普通free波动192512 bytes≈188KiB，未跨37GiB，不能记为实质容量恢复。未重复44候选清理调查。'),
('new storage devices/volumes','无；新增/移除mount与disk identifier均[]，external inventory仍为空。SMB仅空表、NFS无mount；UTM配置/UUID/原bundle路径不变。'),
('candidate backup destinations','新候选0；沿用上轮“无合适独立目标”结论，不重做16项调查、31镜像引用分析或清理。'),
('filesystem per candidate','NOT_APPLICABLE，无新候选；没有可以测试的目标文件系统。'),
('free space per candidate','NOT_APPLICABLE，无新候选；未虚构外盘/NAS/其他UTM目的地。'),
('reliability classification','NOT_APPLICABLE，未进入新设备BACKUP_ONLY/VM_STORAGE_CAPABLE评定；不能宣称不存在设备的可靠性。'),
('sparse semantics test','NOT_TESTED；无新目标，不执行稀疏复制/写入测试。前轮同内部APFS小文件测试不能冒充新目标支持。'),
('conservative backup requirement',f"沿用封存模型 {a['requiredDestinationFreeBytesConservative']} bytes≈{a['requiredDestinationFreeBytesConservative']/G:.2f}GiB，full logical bundle+2GiB余量；不是所有备份表示的数学下界。"),
('sparse-aware backup requirement',f"前轮条件估计≈{a['conditionalSparseDestinationEstimateBytes']/G:.2f}GiB；必须先验证目标稀疏/大文件/完整恢复和静止源，当前NOT_TESTED，不能据此接受仅够207GiB的目标。"),
('selected backup requirement','无可执行选择；保守模型保持约342.69GiB供未来候选验证，实际source/target容量执行前必须重测。新存储class/性能/预算比选未到达。'),
('BACKUP_DESTINATION_READINESS',v['BACKUP_DESTINATION_READINESS']),
('current host free',f"{change['HOST_FREE_AUTHORITATIVE']} bytes≈{change['HOST_FREE_AUTHORITATIVE']/G:.2f}GiB（APFS与df较小值，不计purgeable）。"),
('current host shortage',f"Architecture A距离37GiB尚差{change['hostShortfallBytes']} bytes≈{change['hostShortfallBytes']/G:.2f}GiB。"),
('OPTION A requirements','当前内盘继续运行VM，外盘独立冷备；外盘容纳已验证表示，宿主至少37GiB保留growth16+metadata1+temp4+OSreserve16，并有可验证恢复和维护窗口。'),
('OPTION A verdict','BLOCKED：独立目的地不存在，宿主guard也未满足。完美外盘备份本身不能消除宿主短缺。'),
('OPTION B requirements','未来若有合适外盘：冷clone→offline/隔离验证→保留内部原件为rollback，之后另轮才可考虑主盘。需验证UTM/文件系统/QEMU/稀疏/性能/断连/电源/boot/恢复；外盘成为唯一主盘不等于备份，不能删内部源。'),
('OPTION B verdict','BLOCKED：无external VM candidate；无选定迁移架构，不能用假设的host新guard宣告READY。B的host requirement需按未来实际存储/暂存/保留源布局推导，当前不机械套37或下调。'),
('external-VM performance suitability','NOT_TESTED，无新设备；未做顺序/随机/写入/fsync benchmark，未虚报ACCEPTABLE/MARGINAL/UNSUITABLE。'),
('preferred storage architecture',v['PREFERRED_STORAGE_ARCHITECTURE']),
('rationale','按本轮明确早停规则：no new independent storage且host不足，直接EXTERNAL_CAPACITY_BLOCKED；不把A/B概念模型当可执行架构，不重复旧清理调查。'),
('HOST_CAPACITY_READINESS',v['HOST_CAPACITY_READINESS']),
('selected backup method','无当前可执行方法。条件允许后优先完整cold bundle；精确config/EFI/disk映射沿用封存计划。未开始copy/clone/snapshot。'),
('backup created YES/NO','NO'),
('source VM shutdown YES/NO','NO；没有实际可创建的备份，因此不启动维护/关机。'),
('image-release guard','未到达；源VM仍可管理并提供业务，未shutdown，不能声称VM STOPPED/writerFD=0。沿用fresh-stop/process/全writer检查契约；未重复扫描活盘或执行qemu-img写操作。'),
('backup logical size','NOT_APPLICABLE，无备份；模型大小不是已创建文件大小。'),
('backup physical size','NOT_APPLICABLE，backup byteswritten=0。'),
('backup validation','未执行：无可检查备份；没有source/backup全量hash、backup info/check或restorereceipt。源配置SHA相同不等于备份已验证。'),
('BACKUP_VALIDATION',v['BACKUP_VALIDATION']),
('restore procedure','沿用../trivy-backup-capacity/RESTORE-AND-COLD-BACKUP-PLAN.md，封存未变；原精确bundle/UUID/config/EFI→停止并无占用→验证备份→恢复→UTM附加/boot→root/network/k3s/Jenkins/Harbor/PetClinic验收。禁止覆盖原VM测试。'),
('restore validation level',v['RESTORE_VALIDATION_LEVEL']+'；11项计划约束复核只证明文档/guard，不证明真实恢复。'),
('RESTORE_READINESS',v['RESTORE_READINESS']),
('original VM recovery','未停机，无需恢复/重启；原VM仍为权威且提供实测业务。未迁移、未将外部副本设为primary。'),
('Jenkins health','petclinic-ci #270 SUCCESS，building=false；validation #30 SUCCESS、building=false。V1 summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变。'),
('Harbor health','7/7 Pod Ready，4个受保护digest GET200；当前/上一revision/#214rollback/candidate均保留。image deletion=0，GC执行=0。'),
('K3s/nodes','3 nodes Ready；只读健康快照，不宣称永久可用性；未改k3s或隧道配置。'),
('PetClinic','3/3 Ready，generation175/revision164保持；未改manifest/发布逻辑。'),
('HTTP result','200，沿现有Service访问实测成功。'),
('disk resize count','0；partition grow=0；filesystem grow=0；migration=0。'),
('proxy modification count','0'),
('Trivy DB refresh count','0；Trivy runtime scan=0。'),
('release count','0'),
('rollout count','0'),
('MATERIAL_STORAGE_CHANGE',v['MATERIAL_STORAGE_CHANGE']),
('EXTERNAL_CAPACITY_BLOCKED',v['EXTERNAL_CAPACITY_BLOCKED']),
('STORAGE_EXPANSION_READINESS',v['STORAGE_EXPANSION_READINESS']),
('exact blocker','没有新增可验证独立存储；宿主free约25.21GiB仍不足37GiB。没有新的外部条件就不能创建/验证cold backup或推进恢复/扩盘。既有安全回收0结论未被新证据推翻。'),
('exact next permitted action','接入/挂载一个实际独立存储，或提供已有授权NAS/服务器目标及其可用入口；之后仅对新增目标做容量/大文件/稀疏/可靠性验证与A/B比选。A还需解决宿主约11.79GiB缺口；B按真实布局重算host guard且保留内部原件。本轮到此STOP，不自动继续或周期性重复盘点。'),
]
assert len(rows)==48
head='# EXTERNAL STORAGE GATE — EARLY STOP\n\n本轮检测时间 '+change['time']+'；没有新增存储，按附件明确要求早停。Runtime capability13/16、compatibility2202均保持。不重做host cleanup、registry image引用调查或候选benchmarks。\n\n'
body='\n\n'.join(f'{i}. **{k}**：{text}' for i,(k,text) in enumerate(rows,1))
footer='\n\n## Final verdicts\n\n```json\n'+json.dumps(v,indent=2)+'\n```\n\n验证：Runtime154/154、Regression147/147、Policy core5/5、contract10/10、external/destination纯防护24/24、backup/image guard30/30、既有restore-plan约束11项。synthetic guards不等于真实目标验证；sparse-copy与backup实际验证未适用。455源码引用（229唯一文件）与前轮127文件seal全部未变。\n'
(O/'REPORT-48.md').write_text(head+body+footer)
print(json.dumps({'reportItems':len(rows),'earlyStop':True,'sourceRefs':len(checks),'baselineSealedFiles':len(index['files']),'hostGiB':change['HOST_FREE_AUTHORITATIVE']/G,'shortfallGiB':change['hostShortfallBytes']/G,'protectedState':'PASS','verdict':v},ensure_ascii=False))
