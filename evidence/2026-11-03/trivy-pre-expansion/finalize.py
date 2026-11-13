from pathlib import Path
import json,hashlib,re,sys
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2]
sys.path.insert(0,str(O))
from readiness_guards import resize_ready,image_in_use_guard

def read(n):return json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def gib(n):return f'{n/1024**3:.2f} GiB'
# Historical authoritative manifests: read, never rewrite.
base=json.loads((R/'evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json').read_text())
checks=[{'path':x['path'],'expected':x['expected'],'actual':sha(R/x['path'])} for x in base['checks']]
assert all(x['expected']==x['actual'] for x in checks)
seals=[]
for n in ('runtime-final-three','trivy-infra-repair','trivy-storage-expansion'):
 p=R/'evidence/2026-11-03'/n;index=json.loads((p/'evidence-sha256.json').read_text())
 rows=[{'path':k,'match':sha(p/k)==v} for k,v in index['files'].items()]
 assert all(x['match'] for x in rows)
 seals.append({'directory':str(p.relative_to(R)),'indexSha256':sha(p/'evidence-sha256.json'),'filesChecked':len(rows),'unchanged':True})
policy=R/'infra/security/policy/versions/baseline-v1.json'
assert sha(policy)=='02c3f5499dc39a53009a69e8f267dbbd247b4d89d4de14fafaa4dd5cff974f1a'
save('source-preservation.json',{'checks':checks,'checkCount':len(checks),'uniquePathCount':len(set(x['path'] for x in checks)),'allMatch':True,'priorSeals':seals,'policyBaselineSha256':sha(policy),'compatibilityBaseline':2202,'compatibilityBaselineChanged':False,'scope':'No production source or previous authoritative evidence changed; new work is confined to this evidence directory.'})
cap=read('host-capacity-model.json');vm=read('vm-identity.json');v=read('verdict.json');facts=read('readiness-facts.json');health=read('health-final.json');registry=read('registry-retention-final.json');pre=read('backup-prerequisites-readonly.json');copy=read('copy-tool-fixture.json');plan=(O/'MAINTENANCE-RESTORE-RESIZE-PLAN.md').read_text()
assert not resize_ready(facts['gates'],image_in_use_guard(facts['currentImageUseGuardFacts']))
# These are document/logic assertions only, NOT backup or restore execution.
planchecks={
 'exact_vm_identity_bound':vm['vmIdentity']['UUID'] in plan,
 'exact_original_path_bound':vm['bundle'] in plan,
 'no_invented_backup_target':read('backup-strategy.json')['backupDestination'] is None,
 'clean_shutdown_then_release_then_copy':plan.index('执行 guest `sudo shutdown')<plan.index('必须逐项证明 UTM 报 Stopped')<plan.index('复制完整 bundle'),
 'backup_validation_before_backing_growth':plan.index('离线备份副本')<plan.index('阶段 4：离线 backing'),
 'copy_directory_mapping_explicit':'SOURCE_BUNDLE/ PRECREATED_EMPTY_BACKUP_BUNDLE/' in plan,
 'full_restore_identity_root_network_services':'Jenkins/Harbor、PetClinic endpoints/HTTP' in plan,
 'isolated_boot_all_networking_disabled':'禁用**全部**网络适配器' in plan,
 'shared_production_storage_disabled':'禁用共享宿主可写目录' in plan,
 'clone_ram_budget_explicit':'再起 22 GiB clone 尚未计 OS 就超预算' in plan,
 'never_test_overwriting_current_vm':'不得覆盖当前 VM 来测试恢复' in plan,
 'no_backup_no_restore_claim':v['RESTORE_VALIDATION_LEVEL']=='NOT_VALIDATED' and v['BACKUP_VALIDATION']=='INCOMPLETE',
 'partition_parent_capacity_precondition':'实际为选定 274/290 GiB' in plan,
 'root_start_preserved':'start=2203648' in plan,
 'filesystem_after_partition':plan.index('sudo growpart /dev/vda 2')<plan.index('sudo resize2fs /dev/vda2'),
 'fresh_writer_check_required':'fresh image-in-use guard' in plan,
 'all_gates_block_current_execution':facts['resizeCommandAllowed'] is False,
 'guard_recalculated_after_expansion':'增长后容量' in plan,
 'no_repair_on_mounted_root':'不对已挂载根盘执行修复式 fsck' in plan,
 'restoration_not_shrink':'不采用缩盘逆操作' in plan,
 'real_vm_backup_not_claimed_by_fixture':copy['backupCreated'] is False and copy['productionImageRead'] is False,
}
assert all(planchecks.values()),planchecks
save('restore-plan-validation.json',{'scope':'DOCUMENT_AND_GUARD_VALIDATION_ONLY_NOT_VM_RESTORE','checks':planchecks,'pass':len(planchecks),'fail':0,'actualBackupExists':False,'actualRestoreExecuted':False,'RESTORE_VALIDATION_LEVEL':'NOT_VALIDATED'})
suites=[]
for n,count in [('runtime-tests.log',154),('regression-tests.log',147),('policy-core-tests.log',5)]:
 s=(O/n).read_text();assert re.search(rf'ℹ pass {count}\b',s) and 'ℹ fail 0' in s
 suites.append({'suite':n,'pass':count,'fail':0})
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
assert 'Ran 30 tests' in (O/'readiness-guard-tests.log').read_text() and (O/'readiness-guard-tests.log').read_text().strip().endswith('OK')
save('test-results.json',{'suites':suites+[{'suite':'policy-contract','pass':10,'fail':0},{'suite':'pre-expansion-pure-guards','pass':30,'fail':0}],'restorePlanAssertions':len(planchecks),'copyToolFixture':'PASS_SYNTHETIC_SMALL_FILE_ONLY','compatibilityBaseline':2202,'productionPipelineTriggered':False})
# Preserve exact requested report numbering, with measurements distinguished from not-executed results.
m16,m32=cap['models'];budget=m16['backupBudgetBytes'];disk=vm['bundle']+'/Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2'
rows=[
('VM identity',f"devops / {vm['vmIdentity']['UUID']}，UTM {vm['UTMVersion']}，aarch64，6 CPU，22 GiB RAM。"),
('UTM bundle',vm['bundle']),
('disk path',disk),
('disk format','qcow2 compat1.1，64KiB cluster。'),
('virtual size','277025390592 bytes = 258 GiB。宿主文件逻辑长度 365810089984 bytes，不等于虚拟容量。'),
('allocated host size',f"磁盘 {gib(220095922176)}；bundle {gib(m16['backupSourceAllocatedBytes'])}；活动文件会随写入变化。"),
('backing chain','info --backing-chain 仅一层，无 backing parent。只读元数据，不等于离线完整性 check。'),
('snapshot state','qcow2 info 无 snapshots；Data 卷无 snapshot，tmutil 无本地快照；根系统 sealed snapshot 不是 VM 备份。未证明 UTM4.7.5 可用的恢复型快照。'),
('active QEMU/image-use state','QEMULauncher PID18121，磁盘 FD18 read/write，VM Running；无占用 guard 不通过。未 hash/check 活动整盘。'),
('host filesystem','APFS disk3，physical disk0s2，Data disk3s5，container '+gib(cap['capacityBytes'])+'；container used '+gib(cap['containerUsedBytes'])+'，Data used '+gib(cap['DataCapacityInUseBytes'])+'，quota/reserve=0。'),
('authoritative host free space',f"{cap['HOST_FREE_AUTHORITATIVE']} bytes = {gib(cap['HOST_FREE_AUTHORITATIVE'])}；APFS 与 df 取较小实测值，同 container 挂载不相加。"),
('purgeable/non-guaranteed space','purgeable 未单独报告，不计 guaranteed free；未用缓存、Trash 或 thin provisioned 空间冒充可用容量。'),
('largest host consumers','Library≈265.85GiB（包含活动UTM约205GiB），code≈26.50GiB，Colima≈7.02GiB，Caches≈5.28GiB；嵌套项不叠加。CloudDocs/Google application data 保留。du 有权限缺口。'),
('safe host-reclaim candidates','已有文件无已证实 SAFE_EPHEMERAL 删除集；浏览器/CloudKit缓存、Downloads、Trash、旧日志为 REVIEW_REQUIRED；活动 VM、源码/evidence、Colima RETAIN。详见 host-reclamation-plan.json。'),
('safe reclaim total','0 bytes；未删除现有用户文件。自建64MiB临时稀疏实验文件已清理，不算回收旧文件。'),
('external storage inventory','diskutil external 为空，无挂载 network backup；11个挂载逐项见 external-storage-inventory.json。/Volumes/Recovery 是同一内部 APFS，不是外盘。'),
('external backup suitability','EXTERNAL_BACKUP_STORAGE=NOT_AVAILABLE；没有已验证、空间足够且能容纳单个巨大镜像的目标。'),
('+16 GiB total host requirement',f"当前本地完整备份方案 {gib(m16['localFullBackupScenario']['requiredBytes'])}，预算后差额 {gib(m16['localFullBackupScenario']['remainingBytes'])}；若另有独立外盘，宿主仍需37GiB，外盘另需 {gib(budget)}。"),
('+32 GiB total host requirement',f"当前本地完整备份方案 {gib(m32['localFullBackupScenario']['requiredBytes'])}，预算后差额 {gib(m32['localFullBackupScenario']['remainingBytes'])}；独立外盘条件下宿主53GiB，外盘另需 {gib(budget)}。"),
('HOST_FREE_REQUIRED_MINIMUM',f"{cap['HOST_FREE_REQUIRED_MINIMUM']} bytes = {gib(cap['HOST_FREE_REQUIRED_MINIMUM'])}，适用于当前无外盘拓扑的+16方案。"),
('HOST_FREE_REQUIRED_RECOMMENDED',f"{cap['HOST_FREE_REQUIRED_RECOMMENDED']} bytes = {gib(cap['HOST_FREE_REQUIRED_RECOMMENDED'])}，是+32比较预算，不代表已选择+32。若保留损坏副本并再暂存恢复，另须一份备份预算。"),
('selected expansion size','NO_SAFE_EXPANSION_SIZE_CURRENTLY'),
('expansion rationale','guest available≈43.20GiB，低于 frozen guard≈49.78GiB和preferred52；Harbor/DB缓存及扫描临时文件仍需增长空间。宿主25.13GiB不足任一含备份方案；不能只因thin resize即时写得少而批准。'),
('HOST_CAPACITY_READINESS',v['HOST_CAPACITY_READINESS']),
('selected backup strategy','NONE_CURRENTLY_EXECUTABLE；未来优先 A+D：干净关机＋完整bundle复制至已验证独立外盘。A–F 的一致性、停机、空间、独立性、恢复与风险见 backup-strategy.json。'),
('backup consistency level','实际备份 NONE。计划要求 guest clean shutdown + QEMU完全释放后静态复制；不接受活动 qcow2 copy。不能宣称当前已有application-consistent backup。'),
('backup required size',f"{budget} bytes = {gib(budget)}，bundle逻辑长度+2GiB余量；乐观稀疏分配下限也不适配当前可用容量。"),
('backup destination','NONE；原VM路径已固定，具体备份/恢复暂存目标未具备，不虚构外盘。'),
('backup created','NO；VM未关机，未复制生产镜像。'),
('backup validation','未存在备份，故size/hash/metadata/offline check均未执行。64MiB copy fixture只验证同APFS工具，结果通过且已清理，不能当VM backup。'),
('BACKUP_READINESS',v['BACKUP_READINESS']+'；无容量/目标/可执行策略。已见构建空闲、GC完成、复制为空；手动registry/destructive maintenance无全局排它证明，不当作idle。'),
('BACKUP_VALIDATION',v['BACKUP_VALIDATION']),
('restore procedure','精确原bundle恢复顺序、EFI/config/identity、保留坏副本、启动及root/network/k3s/Jenkins/Harbor/PetClinic验收已写入 MAINTENANCE-RESTORE-RESIZE-PLAN.md。禁止覆盖当前VM测试恢复；执行路径尚未验证。'),
('RESTORE_VALIDATION_LEVEL',v['RESTORE_VALIDATION_LEVEL']+'；当前无备份，连备份 METADATA_ONLY 都不能声称。'),
('RESTORE_READINESS',v['RESTORE_READINESS']+'；备份和恢复暂存容量未验证。隔离clone需全断网/新UUID/MAC/无共享生产写卷；32GiB宿主不能同时承载22+22+2GiB再加OS。'),
('maintenance model','OFFLINE_EXPANSION_REQUIRED；窗口包括暂停新任务、健康快照、干净关机、释放、备份/hash/check、增长、启动和健康恢复；时长未测，不承诺零停机。'),
('image-in-use guard','Stopped＋fresh检查＋目标QEMU/QEMULauncher全退出＋无任意打开FD/写入者＋所有writer检查成功。缺证据、权限失败、Running或旧快照均ABORT；本轮BLOCKED。'),
('VM_MAINTENANCE_READINESS',v['VM_MAINTENANCE_READINESS']+'；容量/备份/恢复与排它维护窗口未满足，未启动停机。'),
('selected backing resize mechanism','拟用完全停机后的 /opt/homebrew/bin/qemu-img resize -f qcow2；不是运行时扩盘，也不编辑plist替代扩盘。'),
('exact proposed resize procedure','全8门禁通过后再次停机/无占用/备份终检→对精确磁盘执行唯一选定 +16G 或 +32G（命令见计划）→info→启动原VM→确认274或290GiB。当前没有选定尺寸，执行0；失败走冷备恢复，禁止缩盘回滚。'),
('BACKING_DISK_RESIZE_READINESS',v['BACKING_DISK_RESIZE_READINESS']),
('partition topology','GPT vda258GiB/512Bsector；vda1 EFI2048–2203647；vda2 root2203648–541065182，最后分区已到最后usable sector；非LVM/MD。'),
('partition grow procedure','更大backing已启动并见guest容量后，保存分区身份→growpart -N /dev/vda 2→核对start/EFI/GUID/type→growpart /dev/vda 2→确认内核新大小。未执行。'),
('GUEST_PARTITION_GROW_READINESS',v['GUEST_PARTITION_GROW_READINESS']+'（独立工具/几何匹配的计划就绪；不代表现在允许执行，parent扩盘和全局门禁仍必需）。'),
('filesystem type','ext4 /dev/vda2；工具resize2fs已存在。当前无24h匹配I/O/ext4错误；mounted needs_recovery是journal标志，不据此诊断损坏。'),
('filesystem grow procedure','只有分区实际变大且无异常，sudo resize2fs /dev/vda2；不mkfs，不重建，不对挂载root做修复式fsck。未执行。'),
('FILESYSTEM_GROW_READINESS',v['FILESYSTEM_GROW_READINESS']+'（独立步骤就绪；执行仍由全局门禁阻断）。'),
('STORAGE_EXPANSION_READINESS',v['STORAGE_EXPANSION_READINESS']),
('resize executed YES/NO','NO；guest分区/文件系统增长也均0。'),
('post-expansion virtual disk size','NOT_APPLICABLE（未扩容）；最近读取仍258GiB。'),
('post-expansion root filesystem size','NOT_APPLICABLE；读取到的现状capacity270430261248 bytes≈251.86GiB，与分区容量不同。'),
('post-expansion available','NOT_APPLICABLE；当前最近filesystem-state样本46387695616 bytes≈43.20GiB；不得当作扩容结果。'),
('STORAGE_EXPANSION_EXECUTION',v['STORAGE_EXPANSION_EXECUTION']),
('production Jenkins state','petclinic-ci #270 SUCCESS / building=false，validation #30 SUCCESS；全jobs active=[]，未触发新构建；V1 summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 不变。'),
('Harbor state','7/7 Pod Ready，未运行新GC、删除或维护。API旧GC为完成态；不据此承诺将来维护窗口已锁定。'),
('K3s/nodes','最近只读取证3/3 Ready，Memory/Disk/PIDPressure=false；未重启k3s或节点。未把短暂快照称永久稳定。'),
('PetClinic','3/3 Ready，业务HTTP200；UID/generation175/revision164与原基线一致，无发布。'),
('protected digest checks','current489cb821…、immediate previous83c2ae78…、documented rollback a8c03e46…、candidate2fbaea65…均GET200，完整digest见registry-retention-final.json；保留其余RS历史与验证依赖。'),
('image deletion count','0（Harbor和containerd镜像均未删）。'),
('proxy modification count','0'),
('Trivy DB refresh count','0；Trivy scan=0。'),
('release count','0'),
('rollout count','0'),
('exact blocking gate if NOT_READY','HOST_CAPACITY不足且EXTERNAL_BACKUP_STORAGE不可用；BACKUP_READINESS未通过→BACKUP_VALIDATION INCOMPLETE→RESTORE_READINESS未通过；维护/扩盘因此NOT_READY。不是growpart/resize2fs缺失。'),
('exact next permitted action','仅验证新可用独立备份目标，保守备份预算≥342.69GiB；同时把宿主实际free补足独立备份条件下+16至少37GiB（尚差约11.87GiB），再重新测算和建立独占维护窗口。也可先为明确的宿主可丢弃文件补引用/所有权证据，不能清理受保护VM、镜像、Colima、源码/evidence。所有条件再通过才执行备份→验证→恢复验证→扩盘。到此STOP。'),
]
assert len(rows)==65
head='# PRE-EXPANSION 最终验收（未扩容）\n\n证据采样：2026-11-03 12:18–12:30 Asia/Shanghai，收口仅写本目录计划/测试/报告；采样不是未来写操作可复用的fresh证明。Runtime capability 13/16，compatibility2202均未提升。\n\n'
body='\n\n'.join(f'{i}. **{k}**：{val}' for i,(k,val) in enumerate(rows,1))
verdict='\n\n## Final verdicts\n\n```json\n'+json.dumps(v,indent=2)+'\n```\n\n'
tests='验证：Runtime154/154、Regression147/147、Policy core5/5、contract10/10、pure guard30/30；恢复文档/guard断言'+str(len(planchecks))+'项。最后两类不是VM备份或恢复执行。冻结源码'+str(len(checks))+'个引用（'+str(len(set(x['path'] for x in checks)))+'个唯一文件）及此前'+','.join(str(s['filesChecked']) for s in seals)+'文件seal全部不变。\n\n参考机制：[QEMU qemu-img](https://www.qemu.org/docs/master/tools/qemu-img.html)、[UTM Resize](https://docs.getutm.app/settings-qemu/drive/resize-and-compress/)；本机实际证据优先，在线文档不证明安装版本的快照/在线扩盘能力。\n'
(O/'REPORT-65.md').write_text(head+body+verdict+tests)
print(json.dumps({'reportItems':len(rows),'sourceChecks':len(checks),'uniquePaths':len(set(x['path'] for x in checks)),'priorSeals':seals,'restorePlanAssertions':len(planchecks),'verdict':v},ensure_ascii=False))
