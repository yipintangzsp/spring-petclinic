"""Local evidence calculations only; no Kubernetes mutation, network, scan or DB refresh."""
import datetime, hashlib, json, math, pathlib, re, subprocess

ROOT=pathlib.Path(__file__).resolve().parents[3]
OUT=pathlib.Path(__file__).resolve().parent
def read(name): return json.loads((OUT/name).read_text())
def write(name,data): (OUT/name).write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
GIB=1024**3
base=read('baseline.json')
before,after=read('trivy-storage-before.json'),read('trivy-storage-after.json')
node=after['nodeFs']; cap=node['capacityBytes']; available=node['availableBytes']
floor=math.ceil(cap*.15+8*GIB); production=cap*.15+12*GIB
host=read('local-backing-storage.json')
common={
 'classification':'READ_ONLY_BUDGET_ASSESSMENT_NO_EXECUTION',
 'sampledAt':after['sampledAt'],'availableBytes':available,'capacityBytes':cap,
 'availableGiB':available/GIB,'validationHardFloorBytes':floor,
 'validationHardFloorGiB':floor/GIB,'belowValidationFloorBytes':max(0,floor-available),
 'productionRefreshRequirementBytes':production,'productionRefreshRequirementGiB':production/GIB,
 'numericGuardChange':False,'hostBackingAvailableBytes':host['availableBytes'],
 'hostBackingAvailableGiB':host['availableBytes']/GIB,'hostCOWPeakUpperBound':'UNKNOWN',
 'guestAndHostBytesAdded':False,
 'storageDomains':[
  {'id':'devops-vda2','observedMount':'/dev/vda2 ext4',
   'writers':['local-path Trivy PVC/cache','container overlay upper/tmp','containerd/node image store','other platform writers'],
   'independentFreeCapacity':False,'mountEvidence':'trivy-filesystem-after.stdout'},
  {'id':'mac-backing','independentStorageLayer':True,'cowAdditionalAllocation':'UNKNOWN',
   'capacityCanBeAddedToGuestFreeBytes':False,'budgetProof':'NOT_PROVEN'}],
 'otherWriterBound':'UNKNOWN','instantaneousWriteAndStopLatencyBound':'UNKNOWN',
 'failureCleanupAdditionalSpace':'UNKNOWN','cleanupContainment':'NOT_PROVEN',
 'pvcDeclared5GiIsEnforcedQuota':False,'measuredPeakIsUpperBound':False,
 'status':'NOT_PROVEN','allowedToExecute':False}
refresh={**common,'operation':'DB_REFRESH_DISK_BUDGET',
 'currentDBLogicalBytes':1666846720,'currentJavaDBLogicalBytes':1564942336,
 'currentDBsAreExistingBaselineNotAdditionalBudget':True,
 'downloadPaths':['/tmp/oci-download-* (current container default temp)','/home/scanner/.cache/trivy/db','/home/scanner/.cache/trivy/java-db'],
 'candidateIsolatedPaths':'owned validation cache and TMPDIR; not created on production this round',
 'components':[
  {'component':'compressed layer','upperBoundBytesAcceptedPerArtifact':1610612736,
   'basis':'unchanged verifyManifest maximum; not actual newly fetched manifest'},
  {'component':'expanded archive plus replacement/old-new overlap','upperBound':'UNKNOWN'},
  {'component':'temporary download/extraction and failed interrupted files','upperBound':'UNKNOWN'},
  {'component':'retained other DB kind during serial refresh','basis':'existing baseline; do not sum independent serial peaks'},
  {'component':'rollback DB copy','additionalCopyCreated':False,'assumedBytes':0}],
 'compressedLimitDoesNotBoundExtraction':True,'peakAdditionalBytes':'UNKNOWN',
 'implementationEvidence':['infra/observability/scanner-db-refresh.mjs',
  'evidence/2026-11-03/trivy-guard-experiment-design/upstream-source/pkg/oci/artifact.go',
  'evidence/2026-11-03/trivy-guard-experiment-design/upstream-source/pkg/db/db.go',
  'evidence/2026-11-03/trivy-guard-experiment-design/upstream-source/pkg/javadb/client.go'],
 'blockers':['BELOW_UNCHANGED_VALIDATION_HARD_FLOOR','EXPANDED_REFRESH_PEAK_UNKNOWN',
  'STOP_LATENCY_WRITE_BOUND_UNKNOWN','FAILURE_CLEANUP_BOUND_UNKNOWN','HOST_COW_BOUND_UNKNOWN','GUARD_CONTAINMENT_GAPS'],
 'refreshCount':0}
scan={**common,'operation':'IMAGE_SCAN_DISK_BUDGET',
 'frozenExecution':'audit requests Harbor scan of selected non-release image digests/architectures; consumes native Harbor reports',
 'paths':['Harbor Trivy cache/fanal','container /tmp and writable layer for unpack/analysis','audit output/report artifacts'],
 'fanalDBLogicalBytes':16777216,'fanalAllocatedBytes':12136448,
 'nodeImageCacheProvesScannerLayerReuse':False,
 'components':[
  {'component':'image layer downloads and cache reuse','upperBound':'UNKNOWN'},
  {'component':'image extraction/analysis temporary files','upperBound':'UNKNOWN'},
  {'component':'fanal cache and native report/artifact writes','upperBound':'UNKNOWN'},
  {'component':'aborted scan cleanup leftovers','upperBound':'UNKNOWN'}],
 'peakAdditionalBytes':'UNKNOWN','freshWarmDBCouldAvoidRefreshBudget':True,
 'currentDBQualifiesAsFreshWarmDB':False,
 'refreshAndScanAreSeparateOperationsButBothNeedOwnSafeBudget':True,
 'frozenScanGateDoesNotItselfRecomputeDatabaseFreshness':True,
 'implementationEvidence':['infra/security/audit-trivy.mjs','infra/observability/scanner-db-refresh.mjs'],
 'blockers':['DB_STALE','DB_FULL_INTEGRITY_UNKNOWN','SCAN_PEAK_UNKNOWN',
  'FAILURE_CLEANUP_BOUND_UNKNOWN','HOST_COW_BOUND_UNKNOWN','NO_VALIDATED_ISOLATED_EXECUTION_PATH'],
 'scanCount':0}
write('db-refresh-disk-budget.json',refresh);write('image-scan-disk-budget.json',scan)
guard={
 'classification':'CONTROLLED_AUDIT_TESTS_NOT_REAL_TRIVY_EXECUTION',
 'productionCompatibility':'VERIFIED','defaultMode':'production','validationModeMustBeExplicit':True,
 'productionFormula':'capacity * 0.15 + 12 GiB','validationHardFloor':'ceil(capacity * 0.15 + 8 GiB)',
 'guardSourceUnchanged':sha(ROOT/'infra/observability/scanner-validation-guard.mjs')=='21c29ecdc38d2f0e20d64fd1d26d22228c680347b44f2a10292c64dbbc928c4a',
 'productionHelperUnchanged':sha(ROOT/'infra/observability/scanner-db-refresh.mjs')=='6e49e8e3d79264e916f0c3c424181ab6e8d15342fcca24a811e3f78de89f306a',
 'numericLimitsChanged':False,'newGuardProductionConnected':False,'executionSafety':'NOT_READY',
 'findings':[
  {'id':'DETACHED_DESCENDANT_ESCAPE','reproduced':True,'severity':'EXECUTION_BLOCKER',
   'evidence':'guard-review-tests.log: owned process group alone does not contain a detached descendant',
   'observed':'receipt processGroupStopped=true while owned detached test descendant still alive',
   'testCleanup':'exact owned escaped group SIGTERM, ESRCH verified, then owned directory removed'},
  {'id':'CACHE_METADATA_SYMLINK_ESCAPE','reproduced':True,'severity':'EXECUTION_BLOCKER',
   'observed':'io.read follows inner metadata symlink to synthetic public sentinel outside cache subtree',
   'deletionEvidence':'recursive rm does not follow that child symlink; no production path touched',
   'remainingRisk':'path/marker lstat-read/removal TOCTOU needs separate no-follow ownership design'},
  {'id':'STORAGE_DOMAIN_COVERAGE_CALLER_DEPENDENCY','reproduced':True,'severity':'EXECUTION_BLOCKER',
   'observed':'synthetic guest-only claimed budget accepted without discovering an omitted physical host',
   'required':'trusted actual-domain inventory and independently reviewed peak/burst/cleanup/COW evidence'},
  {'id':'SAMPLING_CANNOT_PROVE_WRITE_BOUND','severity':'EXECUTION_BLOCKER',
   'observed':'bounded sampling stops on unknown metrics; does not prevent a burst between checks or bound external writers'},
  {'id':'RELEASE_CONTEXT_NOT_SELF_AUTHENTICATED','severity':'ACTIVATION_PREREQUISITE',
   'observed':'explicit validation-only mode required and production rejects validation config; caller must separately bind non-release context'},
  {'id':'NUMERIC_FLOOR_NOT_TUNABLE','status':'VERIFIED','observed':'all accepted constants byte-identical; no threshold bypass added'},
  {'id':'RETRY_REVIEW','status':'VERIFIED','observed':'new validation wrapper has no automatic refresh retry; unchanged production transport route/retry behavior retained'}],
 'reviewTestCount':7,'existingGuardTestCount':73,'actualTotalPassed':80,
 'platformThisRound':'Darwin','newLinuxExecutionClaimed':False,'realScanCount':0,'dbRefreshCount':0}
assert guard['guardSourceUnchanged'] and guard['productionHelperUnchanged']
write('guard-safety-review.json',guard)
options=[
 {'option':'A','name':'existing compliant DB scan','status':'NOT_READY',
  'reasons':['both NextUpdate expired','full DB integrity unknown','separate scan peak/cleanup/COW budget unproven']},
 {'option':'B','name':'bounded DB refresh','status':'NOT_READY',
  'reasons':['free space below unchanged hard floor','expanded peak and burst bounds unknown','cleanup/host-COW bounds unknown','guard containment gaps']},
 {'option':'C','name':'isolated cache/temp work directory on existing storage','status':'NOT_READY',
  'reasons':['isolation adds no capacity','DB copy/cache may add writes','frozen path/topology compatibility not separately proven','all budget and guard blockers remain']},
 {'option':'D','name':'remain blocked','status':'SELECTED',
  'onlyRecommendedNextAction':'separate validation-guard containment and no-follow path hardening under unchanged numeric limits; no refresh/scan activation',
  'doesNotResolveIndependently':['freshness','whole DB integrity','peak/cleanup/burst/host-COW storage proof']}]
write('next-path-assessment.json',{'sevenCandidateAuditRepeated':False,'options':options,'selected':'D'})

# Historical preservation is checked against start-of-round identity, not silently repaired.
changed=[]
for name,expected in base['historicalArtifactsAtStart'].items():
 p=ROOT/name
 if not p.is_file() or sha(p)!=expected: changed.append(name)
protected=[]
for name,expected in base['protectedSeals'].items():
 seal=ROOT/name; assert sha(seal)==expected,name
 files=json.loads(seal.read_text())['files']; mismatches=[]
 for file,h in files.items():
  p=seal.parent/file
  if not p.is_file() or sha(p)!=h:mismatches.append(file)
 protected.append({'seal':name,'files':len(files),'mismatches':mismatches,'sealUnchanged':True})
assert not changed,changed
assert all(not p['mismatches'] for p in protected),protected
oldManifest=ROOT/'infra/security/policy/versions/trivy-parent-baseline-v1.json'
assert sha(oldManifest)==base['oldManifestSha256']
proof=read('versioned-compatibility-proof.json');assert proof['mismatches']==0
assert len(proof['rows'])==184
recovery=[]
for mismatch in base['historicalArtifactSealMismatchesAtStart']:
 name=pathlib.Path(mismatch['path']).name
 candidate=OUT/'original-v1/generated-evidence'/name
 # runner copies the evidence directory itself; locate its unique aggregate if nested.
 if not candidate.exists():
  matches=list((OUT/'original-v1/generated-evidence').rglob(name));assert len(matches)==1
  candidate=matches[0]
 assert sha(candidate)==mismatch['expected'],name
 recovery.append({**mismatch,'supplement':str(candidate.relative_to(ROOT)),
  'supplementMatchesOriginalSeal':True,'historicalFileOverwrittenThisRound':False})
preservation={'historicalFilesCheckedAgainstRoundStart':len(base['historicalArtifactsAtStart']),
 'historicalFilesChangedThisRound':changed,'historicalBundleOriginalSealStatus':'FAILED',
 'preExistingSealMismatches':recovery,'frozenSourceManifestUnchanged':True,
 'oldCodeReproducibility':'VERIFIED','protectedPriorBundles':protected,
 'supplementsDoNotRestoreOriginalEvidenceChain':True}
write('historical-preservation-and-recovery.json',preservation)

testCounts=[]
for name in ['versioned-manifest-tests.log','guard-review-tests.log','regression-tests.log',
 'runtime-tests.log','policy-core-tests.log','helm-shadow-tests.log',
 'original-v1/tests.log','helm-versioned/tests.log','current-lock-failure/tests.log']:
 log=(OUT/name).read_text();row={'log':name}
 for key in ['tests','pass','fail','cancelled','skipped']:
  vals=re.findall(r'(?:#|ℹ) '+key+r' (\d+)\b',log);assert vals,(name,key)
  row[key]=int(vals[-1])
 row['classification']='EXPECTED_SOURCE_IDENTITY_REJECTION' if name.startswith('current-lock-failure') else 'EXECUTED_TEST_SUITE'
 assert row['fail']==(188 if name.startswith('current-lock-failure') else 0)
 testCounts.append(row)
contract=read('policy-contract.json');assert contract['ready'] and len(contract['checks'])==10
testCounts.append({'log':'policy-contract.json','tests':10,'pass':10,'fail':0,
 'classification':'REPEATED_READ_ONLY_CONTRACT_ASSERTIONS_NOT_NEW_AUTHORITATIVE_CASES'})
write('test-results.json',{'suites':testCounts,'realScanCount':0,'refreshCount':0,
 'countsArePerExecutedSuiteNotDistinctTestSum':True})
verdicts={
 'HELM_TRIVY_SOURCE_LOCK_ROOT_CAUSE':'IDENTIFIED',
 'TRIVY_FROZEN_BASELINE_INTEGRITY':'FAILED',
 'TRIVY_VERSIONED_COMPATIBILITY':'VERIFIED',
 'TRIVY_SECURITY_SEMANTIC_DRIFT':'NO',
 'EXISTING_DB_FRESHNESS':'STALE',
 'EXISTING_DB_REAL_SCAN_CANDIDATE':'NO',
 'DB_REFRESH_REQUIRED':'YES',
 'TRIVY_REFRESH_DISK_BUDGET':'NOT_PROVEN',
 'TRIVY_SCAN_DISK_BUDGET':'NOT_PROVEN',
 'TRIVY_GUARD_PRODUCTION_COMPATIBILITY':'VERIFIED',
 'TRIVY_VALIDATION_EXECUTION_READINESS':'NOT_READY',
 'TRIVY_RUNTIME_FACT_CAPTURE':'INCOMPLETE',
 'DEFECTDOJO_RUNTIME_FACT_CAPTURE':'INCOMPLETE',
 'FINAL_WIRED_CAPABILITY':'14/16',
 'REAL_RUNTIME_FACT_CAPTURE':'INCOMPLETE',
 'IMMUTABLE_ARTIFACT_RUNTIME':'INCOMPLETE',
 'SUMMARY_V2_MIGRATION':'INCOMPLETE',
 'RELEASE_COUNT':0,'ROLLOUT_COUNT':0}
assert len(verdicts)==19
write('verdicts.json',verdicts)
(OUT/'VERDICTS.txt').write_text('\n'.join(k+' = '+str(v) for k,v in verdicts.items())+'\nSTOP\n')
rows='\n'.join(f"| {r['log']} | {r['pass']}/{r['tests']} | {r['classification']} |" for r in testCounts)
text=f'''# Trivy 兼容性修复与现有容量执行路径评估

仅本地版本化兼容修复、受控测试和只读取证。真实 DB refresh=0、真实 scan=0、push=0、release=0、rollout=0。未进入 Dojo、Summary V2 或生产 Helm。

## 结论

版本化源码兼容证明 VERIFIED，安全语义漂移 NO；真实执行仍 NOT_READY。选择方案 D，继续阻塞。**原历史证据包的完整性为 FAILED**，不能用新测试通过掩盖。

## 根因矩阵及版本关系

起始 HEAD 为 4de943bb825b1fb74bf2052ee9e95ef4903920d9，c2338e0 确认为其祖先。188 个实际失败逐项归类见 failure-root-cause-matrix.json；全部在 POLICY_ERROR frozen source changed 处退出，没有进入安全决策。13 个原 source-lock 文件中仅 Jenkinsfile.security-audit 身份不同，其余 12 个完全匹配。不是 188 种 Gate 漂移。

| 项目 | 原版本 | Helm integration 版本 |
|---|---|---|
| manifest | trivy-parent-baseline-v1.json | trivy-parent-helm-shadow-v1.json |
| manifest SHA | dc3b95d577707b9d9137663bd88a8034f5ce75f87a377a3504c83afd941a6f8f | e1ac4a6cac7d7282899ece510a411988576a67e272de46f159ddab48ff858ff8 |
| Jenkinsfile SHA | e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2 | 6179859f70c1d6fec2560621ec1ae71dba20514de4ff430d84b7d60a1c319b3c |
| Policy | baseline-v1 | baseline-v1（不变） |

旧 Jenkinsfile 可从 741ea28 Git 对象复现。90b4fca 增加四段 Helm shadow 参数、前置检查、阶段和归档代码；移除已完整验 hash 的这四个明确块后，文本 SHA 精确还原旧值。c2338e0 收紧 Helm 输入校验；4de943b 增加尚未接生产的 validation guard。未改 Trivy 执行命令、漏洞分类、FAIL 条件或报告结构。

新 manifest 明确引用旧 manifest hash；source verifier 钉住新旧两个完整 manifest、13 个 Gate 源文件、33 个 Helm 源文件，拒绝未知 SHA、缺失文件、symlink 或 manifest 篡改。只改 adapter 起始 source-lock 选择，其余 decision body 字节不变。没有删除 SHA 检查、覆盖旧 manifest 或在重放中裁剪新 Jenkinsfile。

原代码+原匹配 Jenkinsfile 190/190；旧 adapter+当前 Jenkinsfile 2/190、188 个预期身份拒绝；新版本+完整当前 Jenkinsfile 190/190。184 个差分记录（54 PASS、130 FAIL）输入摘要、原 Gate 和新旧 Policy 决策全相同；三份汇总输出字节完全一致，另有六项 invariant。上述属于受控重放，不是新扫描或 same-run 16/16。

## 历史完整性异常

本轮开始即发现上轮直接运行测试的 after-hook 覆盖了原 evidence 的三份差分汇总：differential.json、db-differential.json、workflow-differential.json。原 seal 和源 manifest 未改。**这是证据保留错误；原磁盘证据包不能标 VERIFIED。**

本轮全部重放转到临时复制树。旧代码重放恢复的三份汇总分别匹配原 seal 的预期 SHA；仅存入本轮 original-v1/generated-evidence，未覆盖旧证据。historical-preservation-and-recovery.json 记录逐文件异常、补充件及 hash。{len(base['historicalArtifactsAtStart'])} 个历史文件从本轮起点到结束未改；旧 Helm、guard 两个封存包内文件也全部核验未改。可复现的补充件不等于修复原证据保管链。

## 当前 DB 及 freshness

Trivy 实际版本 0.69.3，二进制 SHA d860265c7ebd8128c349d063c91e8f32b26b730d14c2ce85e187fef8be70d72d。仅运行 version、读 metadata/文件 stat/少量 header，未运行扫描。Vulnerability DB schema 2、Java DB schema 1，与当前工具/生产 prerequisite 兼容。

| DB | UpdatedAt UTC | NextUpdate UTC | 逻辑字节 |
|---|---|---|---:|
| db | 2026-10-30T01:01:11.134360213Z | 2026-10-31T01:01:11.134359572Z | 1666846720 |
| java-db | 2026-10-28T01:07:04.331013306Z | 2026-10-31T01:07:04.331012865Z | 1564942336 |

采样 2026-11-04T01:44:11Z。两个 NextUpdate 都过期。实际调用未修改的 requireFreshScannerMetadata，组合和逐 DB 隔离测试均返回 REFRESH_REQUIRED；未改原 metadata。当前 production prerequisite 同时要求两个 DB；不能凭某类镜像可能不查询 Java DB 就省略。原 scan Gate 不自行重算 freshness，DB prerequisite 是独立路径。Trivy 原生短期下载窗口也早已到期。未使用 skip-db-update。

全 DB checksum/页级完整性未验证，仅 header/metadata 不能证明未损坏。现有检查范围内没有同时满足 freshness、完整性和预算的合规缓存候选。结论 STALE、candidate NO、DB_REFRESH_REQUIRED YES；这是前置需求，不是本轮刷新授权。

## 两种磁盘预算

最新 guest sample {after['sampledAt']}：容量 {cap} B，可用 {available} B = {available/GIB:.5f} GiB。validation 固定硬下限 {floor} B = {floor/GIB:.5f} GiB；尚缺 {max(0,floor-available)/GIB:.5f} GiB 才到空载硬下限，尚未计额外写入。production refresh 公式仍 capacity*0.15+12GiB，要求 {production/GIB:.5f} GiB。

Mac backing 另一次只读采样可用 {host['availableBytes']} B = {host['availableBytes']/GIB:.5f} GiB。它是不同层的约束，不可与 guest 相加；COW 增量上界 UNKNOWN。Pod /tmp overlay、PVC cache 和 node/containerd 的底层均落到 guest /dev/vda2，共享容量；5Gi local-path PVC 声明不是已证明的硬配额。

| 预算 | 已知 | 缺失 | 结论 |
|---|---|---|---|
| DB_REFRESH | 旧 DB 约 3GiB 已是基线；压缩 artifact 上限 1.5GiB/件；/tmp/oci-download-* 下载并解压到 cache；两个 DB 串行更新 | 解压/替换/旧新重叠峰值、瞬时写入、失败清理、其他 writer、宿主 COW 均 UNKNOWN | NOT_PROVEN |
| IMAGE_SCAN | Harbor 原生扫描、fanal cache、镜像分析/解压 /tmp、报告写入；与刷新是独立操作 | 精确镜像层缓存复用和解压峰值、报告/清理/外部 writer/COW 上界 UNKNOWN | NOT_PROVEN |

不把串行两个刷新峰值机械相加，不凭 1.5GiB 压缩包上限推导解压上限，不凭 containerd 已有镜像断言 Harbor scanner 已有同一缓存。独立目录不增加容量且可能复制 DB。详见 db-refresh-disk-budget.json 和 image-scan-disk-budget.json。

## Guard 审查

生产默认 delegate 和公式、显式 validation-only 选择、全部参数字节保持不变。原 73 项和新 7 项共 80 项通过；本轮平台 Darwin，未冒称再次执行 Linux 80 项。

受控测试复现三个问题： detached descendant 可逃离进程组而 receipt 仍称 group stopped；metadata 子路径 symlink 可越出 cache 读取 synthetic sentinel；真实 filesystem domain 覆盖仍依赖 caller 证据，guest-only 声明无法自动发现遗漏的物理 backing。逃逸测试的唯一自有进程组已定向停止并验证 ESRCH 后才清理。

指标超时、失去 ownership、磁盘不足可阻止/中止普通路径；采样不能证明瞬时写入上界，也不是 quota。marker/path 操作存在 TOCTOU 边界，正式 release context 需 caller 另行认证。新 wrapper 无自动刷新重试；原 production transport 重试行为不变。以上使 execution readiness 继续 NOT_READY，不能用监控进程代替预算或用调低阈值绕过。guard-safety-review.json 列逐项证据。

## 实际测试

| Suite/log | PASS / total | 分类 |
|---|---:|---|
{rows}

所有数字来自本轮实际日志。Policy Contract 是十条重复只读契约断言，不新增权威 compatibility 样本数。测试只用 synthetic fixtures/隔离复制树，不执行 Trivy。

## 生产状态及交付

只读核验：Jenkins #270 SUCCESS，生产 SCM pin 9a78cc89f22fa98fb1ffcc43e2ae279299471793；V1 Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变。Argo Synced/Healthy、revision 340ef4b8c74e3c2a5820da8d98b0f134283bb8d9；三个 Node Ready，PetClinic 3/3、三个 Ready Endpoint、HTTP 200，Harbor 七个 Pod Ready。Deployment/Service/Ingress/Application UID/spec、生产 image digest 和 Harbor Trivy 配置身份未变。未触发 Jenkins，未改生产代理，未删除数据，未新增高权限资源。

本地只提交范围内八个源码/版本/测试/文档文件，不 push。预存 Policy/Runtime 大量文件尚未纳入 Git，此 scoped commit 不能宣称为独立可发布 checkout。生产入口保持旧 pin，不推广整个主架构。回滚方法见 docs/TRIVY-HELM-COMPATIBILITY-20261104.md：原 adapter+匹配旧 Jenkinsfile 在隔离树已 190/190 验证；不在生产执行回滚。

## 唯一建议下一步

选择 D，继续阻塞。下一轮仅修复 validation guard 的进程 containment 和 no-follow 路径边界，保持所有固定数值、不启用执行。即使修好，DB freshness/完整性、刷新与扫描各自峰值/清理/瞬时写入、其他 writer 与宿主 COW 预算仍需独立证明；不足时不得放行 A/B/C。

## Verdicts

```text
{(OUT/'VERDICTS.txt').read_text().strip()}
```
'''
(OUT/'REPORT.md').write_text(text)
print(json.dumps({'historicalChangedThisRound':len(changed),'priorBundleFileCounts':[p['files'] for p in protected],
 'suiteCount':len(testCounts),'selectedOption':'D','refresh':0,'scan':0},ensure_ascii=False))
