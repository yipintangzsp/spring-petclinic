from pathlib import Path
import hashlib,json,re
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-controlled-six';load=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
before=load(O/'before-sha256.json');changed=[p for p,h in before.items() if not (R/p).is_file() or sha(R/p)!=h]
assert all(p=='Jenkinsfile.runtime-facts' or p.startswith('infra/security/runtime-facts/') for p in changed),changed
oldO=R/'evidence/2026-11-02/runtime-final-eight';oldIndex=load(oldO/'artifact-sha256.json')['files'];assert all(sha(oldO/p)==h for p,h in oldIndex.items())
a=R/'evidence/2026-11-02/summary-integration-readiness-recheck';refs=load(a/'source-integrity.json')['checks'];assert all(sha(R/x['path'])==x['expected'] for x in refs)
indices=load(a/'index-integrity.json')['checks']
for x in indices:
 p=Path(x['path']);p=p if p.is_absolute() else R/p
 if x['directMatch']:assert sha(p)==x['expected']
 else:assert x['resolved'] and sha(R/x['archivedPath'])==x['expected'] and sha(p)==x['actual']
r2=load(R/'infra/security/summary-v2/candidate-integrity-r2.json');assert all(sha(R/p)==h for v in r2['versions'].values() for p,h in v['files'].items())
base=load(oldO/'jenkins-build-12.json');matrix=load(O/'runtime-source-matrix.json');assert matrix['canonicalCount']==16 and matrix['cumulativeWiredCapability']==12 and not matrix['sameBuildCompleteness']
receipts=load(O/'fact-formation-receipts.json')['receipts'];assert len(receipts)==2
for s in receipts:
 assert s['oldDecision']==s['policyDecision']=='PASS' and s['cleanupCompleted'] and not s['failure']
 assert s['evaluationCount']==1 and s['resultDigest']==s['gateResultDigest'];assert s['executionScope']=='CONTROLLED_NON_RELEASE'
for n in [13,14,15,16]:
 b=load(O/f'jenkins-build-{n}.json');assert not b['building'];assert b['build']==n
 assert b['definitionSha256']==sha(O/f'Jenkinsfile.build-{n}') if (O/f'Jenkinsfile.build-{n}').exists() else n==13
 if n in [14,15]:assert b['result']=='SUCCESS' and b['regression'][0]['counts']['tests']==b['regression'][0]['counts']['pass']==147 and b['regression'][0]['counts']['fail']==0
 if n==13:
  # Initial harness defect: old gate exit was FAIL, but dedicated wrapper was
  # initially green. Corrected to propagate oldExit before normal-path build14.
  art=b['artifacts'];s=next(v for p,v in art.items() if p.endswith('/transaction-receipt.json'));assert s['oldExit']==1 and s['oldDecision']==s['policyDecision']=='FAIL' and not s['objects']
for prefix in ['gitleaks-','']:
 cleanup=load(O/(prefix+'boundary-cleanup.json'));assert cleanup['rbacObjectsRemoved']==5 and cleanup['podsRemaining']==0 and cleanup['privateTokenDirectoryRemoved']
rb=[load(O/'gitleaks-minimum-rbac-real-checks.json'),load(O/'minimum-rbac-real-checks.json')];assert all(x['allMatched'] and len(x['checks'])==12 for x in rb)
cleanup=load(O/'final-cleanup-verification.json');assert not cleanup['privateCredentialDirectoryExists'] and not cleanup['guardDirectories'] and cleanup['labeledResourcesRemaining']==0
post=load(O/'node-lease-postflight.json');assert post['lease']['validationHolderReleased'] and all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in post['nodes'])
live=load(O/'live-jenkins-baseline.json');prod=next(j for j in live['jobs'] if j['job']=='petclinic-ci');previous=next(j for j in load(oldO/'live-jenkins-baseline.json')['jobs'] if j['job']=='petclinic-ci')
for k in ['latestBuild','result','summarySha256','checkoutRevisions','scriptPath']:assert prod[k]==previous[k],k
assert load(O/'live-workspace-hashes.json')==load(oldO/'live-workspace-hashes.json')
t0=load(O/'live-target-boundaries.json');t1=load(O/'live-target-boundaries-final.json');assert t0['deployment']==t1['deployment'] and t0['argo']==t1['argo'] and t0['scannerNetworkPoliciesSha256']==t1['scannerNetworkPoliciesSha256']
read=load(O/'readonly-boundary-discovery.json');assert read['externalWriteCount']==0 and len(read['requests'])==5 and all(x['method']=='GET' and x['httpStatus']==200 for x in read['requests'])
assert read['harbor']['identity']['sysadminFlag'] is True
blocks=load(O/'blocked-boundaries.json');assert len(blocks['sources'])==4 and all(x['externalWriteCount']==0 for x in blocks['sources'])
smoke=load(O/'wired-smoke.json');assert smoke['cumulativeWiredCapability']==12 and smoke['policyReevaluations']==0 and smoke['notMergedAcrossBuildBindings']
def tap(file,expected):
 s=(O/file).read_text();c={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',s,re.M)};assert c['tests']==c['pass']==expected and c['fail']==c['skipped']==c['cancelled']==0,(file,c);return {**c,'path':file,'sha256':sha(O/file)}
tests={'collectorOwnerAndGuard':tap('collector-final.log',84),'candidate':tap('candidate-tests.log',40),'policyCore':tap('policy-core.log',5),'gitleaksFrozenParentRecheck':tap('gitleaks-frozen-parent-tests.log',113),'commandFrozenParentRecheck':tap('command-frozen-parent-tests.log',131),'policyContracts':load(O/'policy-contract.json'),'regressionBuild14':load(O/'jenkins-build-14.json')['regression'][0],'regressionBuild15':load(O/'jenkins-build-15.json')['regression'][0],'liveMinimumRbacChecks':[12,12],'authoritativeCompatibilityCount':2202,'compatibilityCountIncremented':False}
assert tests['policyContracts']['ready'] and len(tests['policyContracts']['checks'])==10
replay=load(O/'source-replay-results.json');assert replay['falco']['samples']==replay['falco']['match']==4 and replay['falco']['drift']==0
for r in replay['falco']['records']:
 assert r['oldDecision']==r['policyDecision'] and r['resultDigest']==r['gateResultDigest'] and r['evaluationCount']==1
 if r['kind']=='original-2s-boundary':assert r['oldDecision']=='FAIL'
save('test-results.json',tests)
save('source-preservation.json',{'protectedBaselineFiles':len(before),'allowedExistingFilesChanged':changed,'protectedBaselineFilesUnchanged':len(before)-len(changed),'unauthorizedChanges':[],'frozenSourceReferences':len(refs),'distinctFrozenPaths':len({x['path'] for x in refs}),'indexReferences':len(indices),'previousRoundSealedFilesVerified':len(oldIndex),'r2Unchanged':True,'productionV1WorkspaceUnchanged':True,'productionSummarySha256':prod['summarySha256'],'deploymentUID':t1['deployment']['uid'],'deploymentGeneration':t1['deployment']['generation'],'deploymentSpecSha256':t1['deployment']['specSha256'],'argo':t1['argo'],'initialDeploymentSnapshotScope':'Direct spec snapshot before Semgrep stage; initial Gitleaks protection proven by minimum RBAC deny + guard audit + unchanged V1. Do not claim an earlier unrecorded Deployment spec snapshot.'})
save('validation-outcomes.json',{'builds':[{'number':13,'jenkinsResult':'SUCCESS','actualGate':'FAIL','reason':'Git checkout missing empty refs directory; no Pod created. Wrapper initially did not propagate oldExit. Both harness defects corrected before build14; build13 is not normal scanner completion.'},{'number':14,'jenkinsResult':'SUCCESS','gate':'PASS','source':'gitleaks'},{'number':15,'jenkinsResult':'SUCCESS','gate':'PASS','source':'semgrep-command-audit'},{'number':16,'jenkinsResult':'SUCCESS','scope':'5 real read-only Harbor/Dojo requests, no Policy evaluation'}],'productionBuildsCreated':0,'perBuildPartialProofDoesNotEqualCanonicalCompleteness':True})
leaks=[];scanned=[]
for p in O.rglob('*'):
 if p.is_file() and not p.is_symlink() and p.suffix in ['.json','.log']:
  text=p.read_text(errors='replace');scanned.append(str(p.relative_to(O)))
  if any(re.search(x,text) for x in [r'AGE-SECRET-KEY-1[A-Z0-9]{40,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'"token"\s*:\s*"eyJ[A-Za-z0-9_.-]{80,}']):leaks.append(str(p.relative_to(O)))
assert not leaks,leaks
save('secret-leakage-check.json',{'scope':'Pattern scan and data minimization; no universal leak-proof assertion','scannedFiles':scanned,'matches':leaks,'privateTokenDirectoriesRemoved':True,'productionSopsSecretOrKeyReads':0,'productionSigningKeyReads':0,'rawRuntimeFactsWrittenToDisk':False,'nativeReports':'Gitleaks --redact=100 and validation command/Semgrep native report outputs only'})
verdict={k:'INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']};verdict.update({'canonical':16,'startingWired':10,'newlyWired':['gitleaks','semgrep-command-audit'],'cumulativeWiredCapability':12,'sameBuildComplete':False,'blocked':[s['sourceId'] for s in blocks['sources']],'productionBuildsCreated':0,'validationBuildsCreated':[13,14,15,16],'release':0,'rollout':0,'artifactStatus':'INCOMPLETE','artifactCreated':False,'summaryActivated':False})
save('verdict.json',verdict)
run=load(O/'run.json')['validationRunId'];digestRows='；'.join(r['sourceId']+'='+r['resultDigest'] for r in receipts)
items=[
('starting canonical count','16；原 registry 未改变，Promotion 仍在 pre-approval 集合之外。'),
('starting wired count','10，原 Jenkins #12 证据保持其原 build binding。'),
('exact final-six list','Gitleaks、Semgrep/Command Analysis、Trivy、Cosign、ZAP、DefectDojo；final-six-inventory.json。'),
('side-effect classification per source','前两项 LOCAL_EPHEMERAL_WRITE + TEST_EXTERNAL_WRITE。后四项现有完整父路径含 PRODUCTION_EXTERNAL_WRITE，未执行；禁止 UNKNOWN/IRREVERSIBLE write。'),
('controlled execution boundary per source','前两项：独立 exact tracked HEAD workspace + 短时最小 SA + 命令/Pod/UID guard + 原网络隔离。后四项的具体 blocker 与最小动作见 blocked-boundaries.json。'),
('validationRunId',run+'。Pod 保留原命名语义，通过 build/UID ledger 绑定此 run；管理资源名称含 run ID。'),
('Gitleaks execution/result','#14：真实 frozen parent，当前 source '+receipts[0]['binding']['source']+'，old Gate PASS == Policy PASS；三个实际 scan 调用：原正例、原负例、真实 tracked source。#13 前置失败不计 normal completion。'),
('Gitleaks cleanup','source-14-42491f UID 正常删除并验证 absence；临时 checkout/guard/token 目录移除，5 个短时 SA/RBAC 对象按 UID 删除。'),
('Semgrep/Command Analysis execution/result','#15：原 combined && command，command-audit 与 Semgrep 各执行一个父阶段；old Gate PASS == Policy PASS。'),
('shared-observation/double-count result','canonical=semgrep-command-audit，一次 Policy。实际原 per-file/fixture/repeat core 调用数保存在 fact-formation-receipts.json，未伪称 core 只启动一次；未因多个消费者重跑 source scan。'),
('Trivy execution/result','BLOCKED：Harbor API 架构保持；未用本地 CLI。既有身份是全局 admin，缺最小 validation writer 与已验证的非发布 digest/清理契约。'),
('Harbor write/read boundary','#16：3 次 Harbor GET 200；0 POST/PUT/scan/signature/tag write。active runtime digest 不被当作 disposable artifact。'),
('Cosign execution/result','COSIGN_RUNTIME_BOUNDARY_BLOCKED：冻结 admission 父阶段解密既有 signing bundle 并核对冻结生产公钥；test-only key 不能满足当前信任绑定。'),
('signing/write boundary','生产签名密钥读取/解密=0，新签名=0，registry signature writes=0。独立 VERIFY 不能冒充完整 admission parent。'),
('ZAP execution/result','ZAP_RUNTIME_BOUNDARY_BLOCKED：原代码固定 petclinic Deployment/Service + Jenkins 网络上下文，独立非生产目标尚未满足此冻结入口。'),
('ZAP target identity','只读清单只找到 active production PetClinic；未启动 ZAP、不重定向到生产、不用假的 Kubernetes response 替代目标。'),
('DefectDojo execution/result','DEFECTDOJO_RUNTIME_BOUNDARY_BLOCKED：存在验证 Product，但独立 run Test/cleanup 权限及 Trivy/ZAP 等本轮原生报告尚未建立。'),
('DefectDojo test identity','GET 可见 Product 2 Security Manager Contract Samples / Engagement 2 Shared Library Mode Contracts；它们不是本轮 disposable run identity。配置的正常 Product 1/Engagement 1 未用于写入。'),
('DefectDojo cleanup','未创建/导入/PATCH 任何 Dojo 对象，无测试对象残留；未以纯 mocked API 宣称 real runtime。'),
('new sources successfully wired','Gitleaks、Semgrep/Command Analysis 两项完整原始父阶段。'),
('final wired/16','累计已实现/真实验证 capability=12/16。尚无单次构建 12 项或 16 项全量采集：#12=10，#14/#15 各有当前 Regression + 一个新 source。未跨 build 合并。'),
('blocked sources','Trivy、Cosign、ZAP、DefectDojo；状态保持 BLOCKED，不映射 SKIPPED。'),
('executionScope for all 16','runtime-source-matrix.json；已执行 scope 来源明确，四项 blocked 的 scope 是批准的目标边界，executionStatus=BLOCKED_NOT_EXECUTED，不冒充运行结果。'),
('RuntimeSourceFacts completeness','新两项完整 parent schema / native reports / observations / process / cleanup / classifier facts；旧十项 receipts 校验保持有效；四项缺失，不产生全量 completeness。'),
('per-source evaluation counts','wired-smoke.json：各原 runId+sourceId=1；不同 build 的 Regression 是独立 run，并非同 run 重复。blocked=null。'),
('duplicate-evaluation result','完整 collector/owner suite 中 sequential/concurrent/second-process duplicate fail-closed；本轮 smoke 不求值、不事后去重。'),
('per-source resultDigest',digestRows+'。旧十项完整 digest 见 matrix，保留 #12 binding。'),
('Gate reuse result','owner resultDigest == Gate resultDigest，每条 receipt 逐项断言；Gate 不重读报告再求值。'),
('fact-formation receipts','fact-formation-receipts.json（两条正常路径）及 fact-formation-build-13.json（真实前置失败）；含 input/candidate/build/run、write target、output hash、cleanup、factDigest。'),
('write operations performed','仅临时 scanner Pods、短时 SA/Role/RoleBinding、既有 heavy Lease 生命周期和临时本地报告；具体命令 action/exit 写在 receipts/ledger，外部 release write=0。'),
('external objects created','3 个真实扫描 Pod（Gitleaks 1，audit 1，Semgrep 1）；两轮各 5 个短时身份/RBAC 对象；3 次原 heavy Lease transaction（#13/#14/#15）。'),
('external objects cleaned','3 Pods、10 个临时身份/RBAC 创建实例、heavy Lease 和 token/guard/workspace 目录全部验证删除；无 force/finalizer 操作。'),
('SOPS regression','原 #12 CONTROLLED_ISOLATED_RUNTIME / MIN_RBAC receipt 与 digest 校验通过；不重建测试密钥，不把历史正例改绑定为本轮。'),
('production SOPS Secret/key access','0。'),
('Sonar lineage regression','原 #12 fresh task c146a69e-cb30-4708-9535-d7f923a2ae20 → analysis db7cf501-fc84-40d6-9fbe-a28fb745b94b 的原 binding 校验通过；本轮不新增分析。'),
('Sonar deferred compatibility debt','DEFERRED_REAL_NEGATIVE_EVIDENCE，未升级。'),
('Falco normal regression','baseline/final 两个 ACCEPTED_GATE_REPLAY 正常样本 PASS/PASS，owner=Gate digest；明确非本轮 live sensor 扫描。'),
('Falco 2-second regression','baseline/final 两个 2s 样本 old FAIL == Policy FAIL == owner FAIL，Gate 同 digest；未增加固定 +16s。'),
('canonical completeness','16-set 不变；当前缺四项，且来源保留各原 build binding；不调用全量 completeness 造 COMPLETE。'),
('immutable artifact status','INCOMPLETE，未生成 COMPLETE ImmutablePreApprovalArtifact。'),
('artifact hash','COMPLETE artifact 不存在，hash 不编造。证据集合由 artifact-sha256.json 独立封存。'),
('candidate/build binding','真实 current source + pinned live runtime audit context；新结果分别绑定 #14/#15，不混成一个 build，不宣称新镜像/source attestation。'),
('aggregate Gate','全 16 项 aggregate 尚不可生成。局部构建 #14/#15 SUCCESS 是对应 transaction 成功，不等于全量安全通过。'),
('portability classifications','runtime-source-matrix.json 按 PORTABLE / NEEDS_ADAPTER / PIPELINE_COUPLED / EXTERNAL_SYSTEM_COUPLED 审视；目前每项均有明确依赖，未强行标成 PORTABLE。'),
('pipeline coupling debt','Jenkins workspace/credential/CPS return、Harbor endpoint/repository、Dojo 私有文件和身份、固定 K8s target、toolchain/signing identity；逐来源 futurePluginBoundary 已记录，未实现抽象。'),
('display readiness','新两项包含 source/scope/status/decision/start/end/risk/evidence/fact/result digest；旧十项部分缺 source-level 时间/风险摘要，四项无 runtime，明确 PARTIAL，不宣称 Router/Loki/Grafana 接入。'),
('collector/owner tests','84/84 PASS，包含 owner duplicate、canonical incomplete、artifact refusal、side-effect guard 等。'),
('candidate tests','40/40 PASS，独立可删除测试 checkout。'),
('Policy core','5/5 PASS。'),
('contract tests','10/10 PASS。'),
('Regression 147/147','真实 #14/#15 均 147/147 PASS；#13 前置尝试也 147/147。'),
('final-six specific tests','Gitleaks frozen differential recheck 113/113，Command parent 131/131；在 disposable copy 运行，不覆写旧 evidence。后四项未假称执行；权威累计 2202 不增加。'),
('side-effect guard tests','27 项 guard 测试包含在 84 中：精确 Pod、禁止生产操作、wrong UID/foreign Pod、Git push、Cosign sign、绝对 kubectl、真实 preload 的 execFile/HTTP 禁止路径。后续 guard 加固经本地真实 preload 负向集成；不假称此前 #14/#15 执行了该加固后的字节。'),
('cleanup tests','wrong UID/foreign Pod 拒绝；真实 parent cleanup + 两轮 min-RBAC 12 checks + exact UID 管理清理 + final remote absence checks 通过。'),
('source/hash preservation','source-preservation.json：冻结 455 refs、旧 index、baseline-v1、r2、前轮 87-file seal、active V1 workspace 均核对；变更只在 runtime plumbing/dedicated job/new evidence。'),
('V1 active path','V1 active；Summary SHA '+prod['summarySha256']+' 未变；PetClinic generation '+str(t1['deployment']['generation'])+'、revision '+t1['deployment']['revision']+'、spec hash、3/3 Ready 保持。'),
('production Jenkins state','petclinic-ci #270 SUCCESS；生产 pipeline 未触发。'),
('validation Jenkins builds','#13 前置 FAIL 曾被独立 wrapper 错标 SUCCESS，已修正 oldExit 传播；#14 Gitleaks SUCCESS；#15 combined SUCCESS；#16 read-only discovery SUCCESS。不存在全 16 项成功声明。'),
('release count','0。'),('rollout count','0。'),
('REAL_RUNTIME_FACT_CAPTURE','INCOMPLETE。'),('REAL_POLICY_OWNER','INCOMPLETE。'),('IMMUTABLE_ARTIFACT_RUNTIME','INCOMPLETE。'),('SUMMARY_V2_MIGRATION','INCOMPLETE。'),
('exact blocker if incomplete','四项缺安全的完整 real parent runtime boundary：Harbor admin/validation candidate 与 scoped cleanup；Cosign production-key trust；ZAP 固定 production target；Dojo unique identity/cleanup/native-report 依赖。另无单 build 全量事实，不拼接历史构建。'),
('exact next permitted action if all three runtime verdicts VERIFIED','条件未满足。下一步先收口 scoped test registry identity/candidate，隔离 signing/admission trust 与 ZAP context，以及 Dojo exact-run Test cleanup；验证全部 16 项同 build 后才可生成 COMPLETE artifact。任何情况下本轮 STOP，不启用 Summary V2、不迁移 Promotion/Regression、不启动 Plugin Registry。')]
assert len(items)==66
(O/'REPORT.md').write_text('# Controlled non-release runtime sources：本轮报告\n\n'+'\n\n'.join(str(i)+'. **'+k+'**\n\n   '+v for i,(k,v) in enumerate(items,1))+'\n\n```text\n'+'\n'.join(k+' = INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION'])+'\n```\n')
index={str(p.relative_to(O)):sha(p) for p in sorted(O.rglob('*')) if p.is_file() and not p.is_symlink() and '__pycache__' not in p.parts and p.name!='artifact-sha256.json'};save('artifact-sha256.json',{'files':index});print(json.dumps({'sealedFiles':len(index),'reportItems':len(items),'newSources':2,'cumulativeCapability':12,'sameBuildComplete':False,'blocked':4,'verdicts':'ALL_INCOMPLETE'}))
