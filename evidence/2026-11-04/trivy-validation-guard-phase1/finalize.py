from pathlib import Path
import json,hashlib,subprocess,datetime,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
load=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=load(O/'baseline.json');phase1=load(O/'phase1-acceptance.json');preflight=load(O/'phase2-preflight-proof.json')
assert not preflight['realRefreshAllowed'] and not preflight['phase3Allowed']
for p,h in base['protectedFiles'].items():assert sha(R/p)==h,p
seal_checks=[]
for name,h in base['seals'].items():
 p=R/name;assert sha(p)==h
 seal=load(p)
 for f,expected in seal['files'].items():assert sha(p.parent/f)==expected,f
 seal_checks.append({'path':name,'sha256':h,'filesUnchanged':len(seal['files'])})
before=load(O/'trivy-storage-before.json');after=load(O/'trivy-storage-after.json')
for k in ['statefulsetSpecSha256','environmentConfigurationSha256','pvcs','volumes','pod']:assert before[k]==after[k],k
def db_files(name):
 lines=(O/name).read_text().splitlines()
 return {line.split('|')[0]:line for line in lines if line.startswith('/home/scanner/.cache/trivy/') and '|' in line}
assert db_files('trivy-filesystem-before.stdout')==db_files('trivy-filesystem-after.stdout')
jenkins=next(x for x in load(O/'live-jenkins-final.json')['jobs'] if x['job']=='petclinic-ci')
assert jenkins['latestBuild']==270 and jenkins['result']=='SUCCESS'
old=next(x for x in load(R/'evidence/2026-11-03/helm-shadow-phase1/live-jenkins-final.json')['jobs'] if x['job']=='petclinic-ci')
assert jenkins['summarySha256']==old['summarySha256'] and jenkins['scmBranches']==old['scmBranches']
assert all(any(c['type']=='Ready' and c['status']=='True' for c in n['conditions']) for n in load(O/'node-lease-postflight.json')['nodes'])
health=load(O/'health-final.json');assert health['http']['status']=='200' and health['deployment']['ready']==3
final=load(O/'final-production-verification.json');assert final['readyEndpoints']==3
linux=load(O/'linux-guard-tests.json');assert linux['ownedTemporaryRootAbsent']
for f,h in linux['sourceHashes'].items():assert sha(R/f)==h
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
v={'TRIVY_DUAL_MODE_GUARD':'VERIFIED_IMPLEMENTATION_ONLY','PRODUCTION_GUARD':'UNCHANGED',
 'PHASE1_IMPLEMENTATION':'VERIFIED','PHASE2_REAL_REFRESH':'BLOCKED','CURRENT_TREE_FROZEN_TRIVY_DIFFERENTIAL':'FAILED_SOURCE_IDENTITY',
 'REAL_TRIVY_REFRESH_COUNT':0,'REAL_TRIVY_SCAN_COUNT':0,'TRIVY_STORAGE_ENVIRONMENT':'ENVIRONMENT_BLOCKED',
 'TRIVY_RUNTIME_FACT_CAPTURE':'INCOMPLETE','TRIVY_REAL_GATE_POLICY_EQUIVALENCE':'NOT_TESTED',
 'TRIVY_REAL_POLICY_SINGLE_EVALUATION':'NOT_TESTED','TRIVY_REAL_RESULT_DIGEST_REUSE':'NOT_TESTED',
 'DEFECTDOJO_RUNTIME_DEPENDENCY':'BLOCKED_BY_TRIVY','DEFECTDOJO_SAME_RUN_VALIDATION':'NOT_PERFORMED',
 'DEFECTDOJO_RUNTIME_FACT_CAPTURE':'INCOMPLETE','FINAL_WIRED_CAPABILITY':'14/16',
 'REAL_RUNTIME_FACT_CAPTURE':'INCOMPLETE','REAL_POLICY_OWNER':'INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME':'INCOMPLETE',
 'SUMMARY_V2_MIGRATION':'INCOMPLETE','PRODUCTION_HELM_DEPLOYMENT':'NOT_ACTIVE','RELEASE_COUNT':0,'ROLLOUT_COUNT':0,'STATE':'STOP'}
preserved={'sourceFiles':base['protectedFiles'],'allProtectedSourceBytesUnchanged':True,'oldSeals':seal_checks,
 'productionJenkinsBuild':270,'productionJenkinsResult':'SUCCESS','productionSCMBranchesUnchanged':True,
 'SummaryV1Sha256':jenkins['summarySha256'],'SummaryV1Unchanged':True,'TrivyStatefulSetConfigPodPVCUnchanged':True,
 'TrivyDBFileSizeBlocksInodeMtimeUnchanged':True,'fullDBChecksumRecomputed':False,'productionObjects':final,
 'nodesReady':3,'PetClinicReady':3,'ReadyEndpoints':3,'HTTP':200,'HarborReady':len(health['harborPods']),
 'release':0,'rollout':0,'gitPush':0,'IAMExpansion':0,'privilegedPodsCreated':0,'resourceAuditReopened':False}
for name,value in [('verdict.json',v),('production-preservation.json',preserved),('source-identity.json',{'localCommit':commit,'pushed':False,'files':{p:sha(R/p) for p in ['infra/observability/scanner-validation-guard.mjs','infra/observability/testing/scanner-validation-guard.test.mjs','docs/TRIVY-VALIDATION-GUARD-20261104.md']}}),('stop-receipt.json',{'state':'STOP','localCommit':commit,'phase1ImplementationVerified':True,'realRefreshes':0,'realScans':0,'DojoRuns':0,'release':0,'rollout':0,'SummaryV2Activated':False,'newRuntimeSourceSuccesses':0})]:
 (O/name).write_text(json.dumps(value,indent=2)+'\n')
g=preflight['samples'][0];floor=g['validationHardFloorGiB'];free=g['availableGiB']
lines=['# Trivy validation-only guard / runtime 本轮验收','','本轮停止在真实刷新之前。第一阶段实现通过，第二阶段空间/证据预检拒绝，第三阶段未进入。',
 '',f'本地提交 `{commit}`，未 push。生产 guard/Gate/Summary/发布路径均未改动。',
 '', '1. **Guard 实现与默认行为**：新增显式 production/validation-only facade；原生产 helper 及其 callers 逐字不变，默认不会启用 validation。生产公式仍为 capacity×15%+12GiB。',
 '', '2. **Validation 硬下限与隔离**：采用既有 release stop line ceil(capacity×15%+8GiB)，不可由配置下调；再叠加完整刷新/扫描峰值、瞬时写入、清理和其他写入预算。独立私有临时 cache/tmp、固定 binary/artifact SHA、明确 manifest provider；无生产 proxy/credential/cache 回退。',
 '', '3. **监控与异常清理**：100ms interval / 500ms sample timeout / 1000ms max gap；TERM/KILL 各1000ms。写入上界至少覆盖3600ms完整停止窗口。超时、压力、owner丢失、写入超额、采样失败/间隙和终态未知均失败。只终止自己的 process group；ownership 或进程停止无法证明则拒绝删除。',
 '', '4. **第一阶段测试**：Darwin ARM64 73/73，Linux ARM64 Node20.19.2 73/73；每平台13个真实受控小型 Node 进程用例，使用明确 synthetic 预算，绝非 Trivy DB 执行。已有 Regression147/147、Runtime143/143、Policy core5/5、contract10/10。Linux 两轮临时树均确认清理；首次时序用例失败、修正和清理证据保留。沙箱本地监听 EPERM 首次失败也保留，获准本地监听后完整回归通过。',
 '', '5. **冻结差分的独立阻塞**：当前 tree 的 Trivy frozen differential 共190项，仅2项通过、188项失败，全部受旧 source lock 与已验收 Helm Jenkinsfile 增量 SHA 冲突影响。12个其余冻结源 SHA 一致；本轮未新增该差异，未重写旧清单或绕过检查。此结果不是漏洞 FAIL，不代表旧 Gate 被改变，但不能宣称当前 runtime Policy 已兼容。',
 '', f'6. **当前空间证据**：devops nodeFs/imageFs 是同一 backing，不得相加。可用 {free:.4f} GiB，固定 validation hard floor {floor:.4f} GiB，尚未发生任何新写入即差 {(g["shortfallBeforeAnyAdditionalWritesBytes"]/1024**3):.4f} GiB。生产 refresh 原要求 {g["productionRefreshRequiredBytes"]/1024**3:.4f} GiB。Mac backing 可用约 {preflight["localBacking"]["availableGiB"]:.4f} GiB，不是额外独立 guest 空间。',
 '', '7. **预算证明**：刷新 old/new/压缩/解压/temp/扫描报告峰值、停止延迟内瞬时写入、失败清理和物理 COW 上界均未建立。没有用监控替代预算，没有以压缩包大小冒充展开峰值，没有新造 PROVEN 文件。因此 BLOCKED_DO_NOT_REFRESH，阈值未反复下调。',
 '', '8. **真实执行与 Trivy 接线**：DB refresh0、native scan0、报告0；旧 Gate vs Policy真实差分、单次求值、resultDigest复用均 NOT_TESTED。仅新增未激活的 guard/隔离 refresh IO 实现，未接入当前 Jenkins runtime，不伪造 native report。',
 '', '9. **Dojo 接线**：BLOCKED_BY_TRIVY，本轮0次；没有使用其他轮报告拼接 same-run 16/16。',
 '', '10. **生产保护**：三个节点 Ready，PetClinic3/3、3个Ready Endpoint、HTTP200，Harbor7个Ready Pod。Jenkins生产#270 SUCCESS，V1 Summary SHA、SCM pin、Argo Application/Deployment/Service/Ingress UID及spec、生产digest未变；Argo Synced/Healthy。Trivy StatefulSet/环境配置hash/Pod/PVC/DB文件块数inodemtime未变（未重算整个DB SHA）。Helm证据及旧实验/资源审计封存均逐文件校验未变。',
 '', '11. **权限/清理/变更范围**：只新增3个源码/测试/文档文件，本地提交；无 IAM 扩权、无 privileged Pod、无 Kubernetes资源创建、无 Jenkins任务或生产配置修改。Linux测试仅现有容器中的已知临时目录与普通子进程，两轮目录均已确认不存在。',
 '', '12. **下一步允许操作**：STOP。资源审计仍 CLOSED。只有现有资源发生实质变化且完整的 reviewed artifact-bound peak/burst/cleanup/backing预算可验证满足固定底线，才可另行进行 validation-only预检。先通过明确版本化、审查过的源码兼容迁移解决 Helm raw SHA 与旧 Trivy lock 的冲突；保留历史清单，不绕过。条件全部满足后才允许同轮真实刷新/扫描→旧Gate/Policy/单次求值/digest验证→同轮Dojo。不得启用 SummaryV2/主架构，不推进 Helm迁移。',
 '', 'Evidence: phase1-acceptance.json, phase2-preflight-proof.json, frozen-source-diagnosis.json, production-preservation.json, linux-guard-tests.json, linux-initial-test-cleanup.json, all test logs.',
 '', '```text']+[k+'='+str(value) for k,value in v.items()]+['```','','STOP。']
(O/'REPORT.md').write_text('\n'.join(lines)+'\n')
print(json.dumps({'phase1':'VERIFIED_IMPLEMENTATION_ONLY','realRefresh':'BLOCKED','commit':commit,'sourceSealsUnchanged':sum(s['filesUnchanged'] for s in seal_checks),'state':'STOP'}))
