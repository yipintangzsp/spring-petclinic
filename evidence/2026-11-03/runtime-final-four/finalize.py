from pathlib import Path
import json,hashlib,re
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-final-four';load=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
before=load(O/'before-sha256.json');changed=[p for p,h in before.items() if not (R/p).is_file() or sha(R/p)!=h];assert all(p=='Jenkinsfile.runtime-facts' or p.startswith('infra/security/runtime-facts/') for p in changed),changed
prior=R/'evidence/2026-11-03/runtime-controlled-six';index=load(prior/'artifact-sha256.json')['files'];assert all(sha(prior/p)==h for p,h in index.items())
a=R/'evidence/2026-11-02/summary-integration-readiness-recheck';refs=load(a/'source-integrity.json')['checks'];assert all(sha(R/x['path'])==x['expected'] for x in refs)
indices=load(a/'index-integrity.json')['checks']
for x in indices:
 p=Path(x['path']);p=p if p.is_absolute() else R/p
 if x['directMatch']:assert sha(p)==x['expected']
 else:assert x['resolved'] and sha(R/x['archivedPath'])==x['expected'] and sha(p)==x['actual']
r2=load(R/'infra/security/summary-v2/candidate-integrity-r2.json');assert all(sha(R/p)==h for v in r2['versions'].values() for p,h in v['files'].items())
base=load(O/'baseline.json');
for f in ['owner.mjs','collector.mjs','projection.mjs']:
 p='infra/security/runtime-facts/'+f;assert sha(R/p)==base['implementationHashes'][p]
assert sha(R/'infra/security/summary-v2/inventory.mjs')==base['canonicalSourceManifestSha256']
build=load(O/'jenkins-build-20.json');assert build['build']==20 and build['result']=='SUCCESS' and not build['building'];get=lambda s:next(v for p,v in build['artifacts'].items() if p.endswith('/'+s))
receipt=get('zap-runtime-receipt.json');assert receipt['oldDecision']==receipt['policyDecision']=='PASS' and receipt['evaluationCount']==1 and receipt['resultDigest']==receipt['gateResultDigest'] and receipt['cleanupCompleted'] and not receipt['error']
result=get('zap.result.json');capture=get('zap.capture.json');gate=get('zap.gate.json');assert result['resultDigest']==capture['resultDigest']==gate['resultDigest']==receipt['resultDigest'];assert result['rawFactDigest']==capture['rawFactDigest']==receipt['factDigest'];assert result['binding']==receipt['binding'] and result['binding']['build']==20
assert result['result']['policyVersion']=='baseline-v1' and result['result']['securityLevel']=='standard' and result['evidenceComplete'];assert capture['rawPayloadPersisted'] is False
assert any(e.get('executionScope')=='CONTROLLED_NON_RELEASE' for e in capture['evidence'])
assert get('zap-min-rbac.json')['allMatched'] and len(get('zap-min-rbac.json')['checks'])==12
snapshot=get('owner-snapshot.json');assert set(snapshot['evaluationCounts'])=={'regression','zap'} and all(v==1 for v in snapshot['evaluationCounts'].values());assert len({r['resultDigest'] for r in snapshot['sources']})==2
for s in snapshot['sources']:assert s['resultDigest']==snapshot['gate'][s['sourceId']]['resultDigest']
assert load(O/'native-report-identity-checks.json')['allMatched']
cleanup=load(O/'zap-cleanup.json');assert cleanup['namespaceRemoved'] and cleanup['tokenDirectoryRemoved'];assert len(cleanup['objectsRemoved'])==11
assert load(O/'zap-precleanup-ownership.json')['allForeignWorkloadChecksPassed'];absent=load(O/'final-private-resource-absence.json');assert absent['namespaceAbsent'] and all(x['absent'] for x in absent['checks']);assert load(O/'build-18-temp-cleanup.json')['allAbsent']
target=load(O/'zap-target-final-proof.json');assert target['actualH2ConnectionObserved'] and target['readyReplicas']==1 and target['allObservedMethodsGet'] and target['productionTargetHttpRequests']==0 and not target['productionDatabaseCredentialsUsed']
assert load(O/'local-validation-image.json')['digestMatches'] and load(O/'local-validation-image.json')['credentialUsed'] is False
net={n['name']:n['spec'] for n in target['networkPolicySpecs']};assert net['deny-all'].get('egress',[])==[] and net['deny-all'].get('ingress',[])==[] and set(net['deny-all']['policyTypes'])=={'Ingress','Egress'};assert net['scanner-to-validation-only']['egress'][0]['to']==[{'podSelector':{'matchLabels':{'runtime-validation-app':receipt['validationRunId']}}}]
for n in [17,18,19,20]:
 b=load(O/f'jenkins-build-{n}.json');assert not b['building'];assert b['definitionSha256']==sha(O/f'Jenkinsfile.build-{n}')
 if n==18:assert b['result']=='FAILURE' and not b['artifacts']
 if n==19:
  r=next(v for p,v in b['artifacts'].items() if p.endswith('/zap-runtime-receipt.json'));assert b['result']=='FAILURE' and r['oldDecision']==r['policyDecision']=='FAIL' and r['cleanupCompleted']
bundle=load(O/'build-20-runtime-source-bundle.json');generated=set(bundle['generatedGitMetadataFiles'])|{'runtime-sbom-clean-source.tar.gz','runtime-sbom-clean-source.json','runtime-sonar-origin.json','runtime-validation-run.json','runtime-accepted-baseline.json','runtime-accepted-extra.json'};assert all(p in generated or sha(R/p)==h for p,h in bundle['files'].items())
assert build['definitionSha256']==sha(R/'Jenkinsfile.runtime-facts')
live=load(O/'live-jenkins-baseline.json');prod=next(j for j in live['jobs'] if j['job']=='petclinic-ci');old=next(j for j in load(prior/'live-jenkins-baseline.json')['jobs'] if j['job']=='petclinic-ci')
for k in ['latestBuild','result','summarySha256','checkoutRevisions','scriptPath']:assert prod[k]==old[k],k
assert load(O/'live-workspace-hashes.json')==load(prior/'live-workspace-hashes.json')
t0=load(O/'live-target-boundaries.json');t1=load(O/'live-target-boundaries-final.json');assert t0['deployment']==t1['deployment'] and t0['argo']==t1['argo'] and t0['scannerNetworkPoliciesSha256']==t1['scannerNetworkPoliciesSha256']
post=load(O/'node-lease-postflight.json');assert post['lease']['validationHolderReleased'] and all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in post['nodes'])
def tap(file,expected):
 t=(O/file).read_text();v={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',t,re.M)};assert v['tests']==v['pass']==expected and v['fail']==v['skipped']==v['cancelled']==0,(file,v);return {**v,'path':file,'sha256':sha(O/file)}
tests={'collectorRuntime':tap('collector-final.log',114),'sideEffectGuardSubset':{'total':49,'existingGuard':27,'zapBoundary':22,'includedInRuntime114':True},'candidate':tap('candidate-tests.log',40),'policyCore':tap('policy-core.log',5),'contract':load(O/'policy-contract.json'),'trivyFrozenTests':tap('trivy-source-tests.log',129),'cosignFrozenTests':tap('cosign-source-tests.log',268),'zapFrozenTests':tap('zap-source-tests.log',177),'dojoFrozenTests':tap('dojo-source-tests.log',69),'negativeCompleteness':tap('completeness-negative.log',8),'liveRegression':build['regression'][0],'authoritativeCompatibilityCount':2202,'compatibilityCountIncremented':False}
assert tests['contract']['ready'] and len(tests['contract']['checks'])==10;assert tests['liveRegression']['counts']['tests']==tests['liveRegression']['counts']['pass']==147 and tests['liveRegression']['counts']['fail']==0
replay=load(O/'source-replay-results.json');assert replay['falco']['samples']==replay['falco']['match']==4 and replay['falco']['drift']==0
for r in replay['falco']['records']:
 assert r['oldDecision']==r['policyDecision'] and r['resultDigest']==r['gateResultDigest'] and r['evaluationCount']==1
 if r['kind']=='original-2s-boundary':assert r['oldDecision']=='FAIL'
save('test-results.json',tests)
trivy=load(O/'trivy-permission-boundary.json');cosign=load(O/'cosign-boundary-review.json');dojo=load(O/'dojo-boundary-review.json');assert trivy['identityCreated'] is False and trivy['scanTriggers']==0 and cosign['productionKeyAccess']==cosign['testKeysGenerated']==cosign['signaturesCreated']==0 and dojo['importRequests']==0 and not dojo['independentIdentityCreated']
matrix=load(O/'runtime-source-matrix.json');assert matrix['individualWiredTotal']==13 and matrix['sameRunSourceCount']==2 and not matrix['allFourIndividuallyClosed'] and len(matrix['missingSameRunSources'])==14
sources=matrix['sources'];required=['sourceId','executionScope','executionStatus','decision','startedAt','completedAt','evidenceRef','factDigest','resultDigest'];assert all(all(k in s for k in required) for s in sources)
save('display-contract-readiness.json',{'scope':'Readiness inventory only, not Unified Summary/Router integration','sourceCount':16,'requiredFields':required,'sources':[{k:s.get(k) for k in required} for s in sources],'completeForAll16':False,'missingRuntimeSources':['trivy','cosign','defectdojo'],'historicalMetadataGaps':[s['sourceId'] for s in sources if s['resultDigest'] and (s['startedAt'] is None or s['completedAt'] is None)],'doNotInterpretNullsAsPass':True})
save('source-preservation.json',{'baselineFiles':len(before),'allowedExistingFilesChanged':changed,'unauthorizedChanges':[],'protectedBaselineFilesUnchanged':len(before)-len(changed),'frozenSourceReferences':len(refs),'distinctFrozenPaths':len({x['path'] for x in refs}),'indexReferences':len(indices),'priorIterationSealedFilesVerified':len(index),'r2Unchanged':True,'baselineOwnerCollectorProjectionUnchanged':True,'canonicalManifestUnchanged':True,'productionV1WorkspaceUnchanged':True,'summarySha256':prod['summarySha256'],'deployment':t1['deployment'],'argo':t1['argo'],'originalScannerNetworkPoliciesUnchanged':True})
save('fact-formation-receipts.json',{'sources':[{'sourceId':'trivy','executionScope':'CONTROLLED_NON_RELEASE','executionStatus':'BLOCKED_NOT_EXECUTED','scopeMeaning':'required validation boundary, not an executed result','validationRunId':receipt['validationRunId'],'credentialIdentity':None,'minimumPermissions':trivy['scopeLimitation'],'inputIdentity':trivy['candidate'],'externalObjectsCreated':[],'externalObjectsModified':[],'externalObjectsDeletedRetained':'Existing candidate retained, no mutations','factDigest':None,'resultDigest':None,'cleanupResult':'NOT_NEEDED_NO_WRITES'},{'sourceId':'cosign','executionScope':'CONTROLLED_NON_RELEASE','executionStatus':'BLOCKED_NOT_EXECUTED','scopeMeaning':'required validation boundary, not an executed result','validationRunId':receipt['validationRunId'],'credentialIdentity':None,'minimumPermissions':'Test-only registry writer + independent validation trust, not yet established','externalObjectsCreated':[],'externalObjectsModified':[],'factDigest':None,'resultDigest':None,'cleanupResult':'NO_KEY_OR_SIGNATURE_CREATED'},load(O/'zap-fact-formation-receipt.json'),{'sourceId':'defectdojo','executionScope':'CONTROLLED_NON_RELEASE','executionStatus':'BLOCKED_NOT_EXECUTED','scopeMeaning':'required validation boundary, not an executed result','validationRunId':receipt['validationRunId'],'credentialIdentity':'Existing read-only inspection identity only; not a new validation writer','minimumPermissions':dojo['missing'],'externalObjectsCreated':[],'externalObjectsModified':[],'factDigest':None,'resultDigest':None,'cleanupResult':'NO_IMPORT_OR_VALIDATION_OBJECT_CREATED'}]})
formed=load(O/'fact-formation-receipts.json')
for r in formed['sources']:
 r.setdefault('inputIdentity',None);r.setdefault('externalObjectsCreated',[]);r.setdefault('externalObjectsModified',[]);r.setdefault('externalObjectsDeletedOrRetained',[]);r.setdefault('rawReportIdentity',None)
 if r['sourceId']=='zap':
  r['executionStatus']='COMPLETED';r['inputIdentity']=target;r['externalObjectsCreated']=load(O/'zap-object-ledger.json')+get('zap-boundary-audit.json')['objects'];r['externalObjectsModified']=[load(O/'zap-validation-image-transport-change.json')];r['externalObjectsDeletedOrRetained']=cleanup['objectsRemoved']+receipt['scannerCleanupChecks'];r['rawReportIdentity']=receipt['rawReports'];r['cleanupResult']=cleanup
save('fact-formation-receipts.json',formed)
save('validation-outcomes.json',{'builds':[{'build':17,'result':'SUCCESS','scope':'10 actual read-only permission/candidate requests; no Policy evaluation'},{'build':18,'result':'FAILURE','scope':'Rejected unsupported targetScope before scanner; owned setup temp roots independently removed; binding uses existing runtime schema from build19 onward'},{'build':19,'result':'FAILURE','oldGate':'FAIL','policy':'FAIL','reason':'Real ZAP lifecycle completed scan; validation wrapper wrongly rejected already-absent Pod during original cleanup polling; physical scanner absence confirmed, original Gate unchanged'},{'build':20,'result':'SUCCESS','oldGate':'PASS','policy':'PASS','reason':'Wrapper cleanup absence logic corrected; full frozen validation-target execution, exact digest reuse and native archive hashes match'}],'productionBuildsCreated':0,'single16RunAttempted':False})
leaks=[];scanned=[]
for p in O.rglob('*'):
 if p.is_file() and not p.is_symlink() and p.suffix in ['.json','.log']:
  t=p.read_text(errors='replace');scanned.append(str(p.relative_to(O)))
  if any(re.search(v,t) for v in [r'AGE-SECRET-KEY-1[A-Z0-9]{40,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'"token"\s*:\s*"eyJ[A-Za-z0-9_.-]{80,}']):leaks.append(str(p.relative_to(O)))
assert not leaks,leaks
save('secret-leakage-check.json',{'classification':'Pattern scan plus controlled data minimization, not universal leak proof','files':scanned,'matches':[],'productionSopsSecretAccess':0,'productionAgePrivateKeyAccess':0,'productionSigningKeyAccess':0,'temporaryTokenRemoved':True,'testCosignPrivateKeyCreated':False,'noCredentialMaterialInEvidence':True})
verdict={k:'INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']};verdict.update({'canonical':16,'startingWired':12,'newlyWired':['zap'],'individualWiredTotal':13,'blocked':['trivy','cosign','defectdojo'],'sameRunBuild':20,'sameRunSourceCount':2,'sameRunMissing':matrix['missingSameRunSources'],'sameRun16Attempted':False,'artifactCreated':False,'artifactStatus':'INCOMPLETE','summaryActivated':False,'productionBuildsCreated':0,'validationBuildsCreated':[17,18,19,20],'release':0,'rollout':0});save('verdict.json',verdict)
items=[
('starting wired count','12；已冻结 branch '+base['branch']+' / commit '+base['commit']+'、runtime-facts/owner/projection/collector/schema/V1 hashes 和回滚命令，见 baseline.json / rollback-commands.txt。'),
('final-four blocker matrix','final-four-boundary-matrix.json 在所有本轮执行前建立；各项原实现、依赖、凭据、写入、绑定、facts、最早边界、对象、清理、权限、fallback 和 blocker 均已记录。'),
('validationRunId',receipt['validationRunId']+'；日期按 Asia/Shanghai，执行记录原始时间戳为 UTC。'),
('Trivy minimum-permission identity','未创建。运行中 Harbor 的 RobotPermission schema 按 project/system namespace + resource/action/effect 配置，没有 per-digest 条件；不能在冻结固定共享 project 中证明仅验证候选可 scan-create。详情 trivy-permission-boundary.json。未授予 push/delete/admin。'),
('Trivy candidate image','真实只读识别到已有非发布候选 '+trivy['candidate']['digest']+'，tag 0.10.0-ci-1000002，amd64/arm64；未新建镜像。tag immutable=false，未把它宣称为本轮可完整运行的安全候选。'),
('Trivy execution scope','要求 CONTROLLED_NON_RELEASE，实际 runtime NOT_EXECUTED；只有 LIVE_READ_ONLY metadata/permission/candidate inspection。'),
('Trivy runtime result','BLOCKED，无 scanner/Policy result，不替换本地 CLI，不拿历史报告当本次 facts。'),
('Trivy cleanup','0 新 artifact/tag/robot/scan write；历史非发布 artifact 明确保留，未删除既有数据。'),
('Cosign production-key access count','0。'),
('Cosign validation key/signature scope','先盘点 verification / signing / candidate binding 三类事实；完整 canonical admission 还需要独立 registry writer 与 test-only admission trust。安全前提未齐，未生成无用途测试 key，也未以 VERIFY-only 替代完整父阶段。'),
('Cosign runtime result','BLOCKED：test-only key 本身不能替代当前完整 registry/admission 绑定；不使用 production private key，不改现有信任策略。'),
('Cosign cleanup','新私钥/密码/签名/registry 对象=0，无残留。'),
('ZAP validation target','namespace '+receipt['target']['namespace']+'，真实 Deployment/Service petclinic；相同应用 digest 通过只读校验本地 registry manifest 复用；只连接 jdbc:h2:mem:runtimevalidation，无 PVC/生产 Secret/生产 DB。'),
('ZAP production-target access count','实际 DAST/HTTP 访问生产目标=0。基线仅只读生产 Kubernetes 元数据以记录 digest 和禁止的 Service IP；扫描调用由 guard 映射真实验证对象，CNI default-deny 仅允许 scanner→validation app:8080。'),
('ZAP runtime result','#20 SUCCESS；old Gate PASS == Policy PASS，完整原 passive stage/三次原 scan 生命周期/原 synthetic auth probes 均真实执行。#19 清理 wrapper 缺陷导致真实 FAIL/FAIL，保留证据，未重写为 PASS。'),
('ZAP cleanup','2 个原扫描 Pod（#19/#20）UID 删除确认；11 个直接创建对象、Deployment 所属 Pod/ReplicaSet、namespace、min-RBAC/token/本地 workspaces 均清理；独立 remote absence 检查通过。'),
('DefectDojo validation identity','未创建；现有非 staff CI 身份读取 /api/v2/users/ 实际 403，无已建立的合法最小账号/token provision 管理入口和清理权限；未提权或借用生产写身份。'),
('DefectDojo Product/Engagement/Test IDs','只有既有验证 Product 2 / Engagement 2 的只读观察；本轮新 Product/Engagement/Test IDs=[]，未重用 production Tests。'),
('DefectDojo import/query-back result','未执行。除权限外，真实 frozen full parent 还需要完整本轮 Trivy、4份 Kubescape、Gitleaks、Semgrep、ZAP、Sonar 原生报告链，当前不齐；不以单个报告/纯 mocked API 冒充完整父阶段。'),
('DefectDojo cleanup/retention','0 imports/reimports/PATCH/deletions；既有 production/validation records 未被本轮写入。'),
('final-four source-specific result IDs','ZAP='+receipt['resultDigest']+'；另外三项未生成 resultId。'),
('final-four Policy evaluation counts','ZAP #20=1；Trivy/Cosign/Dojo=0（未执行）。#19 是另一个真实失败 run，单独=1，不与 #20 混合。'),
('final-four Gate digest reuse','ZAP owner.resultDigest == Gate.resultDigest；逐文件 capture/result/Gate 校验；其他三项 N/A，不假造 Gate。'),
('previously wired 12 regression','#20 前后真实执行 twelve-smoke：原 14 条 receipts 对应 12 个 capabilities，校验原 binding/schema/hash/count，不再求值、不将旧结果改绑成本次。collector 兼容性测试也通过。'),
('individual wired total','13/16，新增 ZAP。'),
('same-run canonical validation build','未触发全 16 项运行，因为其余三边界尚未 individually closed；#20 是 ZAP transaction validation，不冒称全量 canonical run。'),
('same-run source count','#20 当前真实观察=2：Regression、ZAP。'),
('missing same-run sources',', '.join(matrix['missingSameRunSources'])+'。其中已在其他原 build 验证的来源仅作 smoke；未拼接。'),
('duplicate source check','#20 两个 sourceId/resultDigest distinct，每项一次。前置 canonical manifest 仍 16，无 alias/Promotion 新增。'),
('cross-run stale result rejection','standalone completeness-negative 8/8 含 wrong runId / previous-build receipt / wrong candidate；candidate suite 40/40 含 stale source/build/project/job；旧 #12/#14/#15 未合并。'),
('fact contract completeness','ZAP 真实完整 facts 经现有 frozen adapter；native report 字节哈希与 Jenkins 归档完全一致。Trivy/Cosign/Dojo 没有 runtime envelope，不映射 SKIPPED。'),
('16/16 canonical completeness','INCOMPLETE；expected 16，当前 #20 observed 2；未降低 validator。'),
('immutable artifact path','无 COMPLETE artifact path。'),('artifact hash','未生成 artifact，因此不编造 artifact hash；证据目录有独立 artifact-sha256.json seal，不与 runtime artifact 混淆。'),
('same-run binding result','#20 两个实际结果同 job/build/runId/source/candidate binding，验证通过；这不等于全 16 项 binding proof。'),
('candidate/build binding','验证目标使用 '+receipt['binding']['candidate']+'，原 namespace/真实 Service IP/Pod imageID 记录可追溯；应用镜像复用已有 build，不伪称由当前 collector source 重新构建或签名 attestation。'),
('aggregate Gate result','只复用单项 Gate；全 16 aggregate 未生成，不从部分 PASS 推断全量 PASS。'),
('all-source evaluation counts','runtime-source-matrix.json 保留各原 build 的一次求值证据；#20 counts={regression:1,zap:1}。未执行来源=0，无 Summary/Promotion 求值。'),
('all-source Gate resultDigest reuse','原 12 receipts 保留既有相同 digest；新 ZAP 同 digest；未声称缺失三项已有 Gate。'),
('negative completeness tests','8/8：missing、duplicate、wrong run、stale build、wrong candidate、invalid/tampered factDigest、invalid resultDigest、malformed status；仅 SYNTHETIC_UNIT_ONLY/in-memory，不作为真实 COMPLETE。'),
('Falco normal regression','ACCEPTED_GATE_REPLAY baseline/final 各一个 normal PASS/PASS；明确不是本轮新 live sensor 结果。'),
('Falco 2-second regression','两个 2s 原边界 old FAIL == Policy FAIL == owner FAIL，Gate 同 digest；固定 +16s 未引入。'),
('SOPS production access counts','生产 Secret=0，生产 age private key=0；原 #12 CONTROLLED_ISOLATED_RUNTIME/MIN_RBAC receipt 不变；本轮未重建/访问生产凭据。'),
('Sonar lineage regression','原 #12 current-build fresh task→analysis→server Quality Gate 原关联与 binding 保持；本轮不把历史结果伪装成新分析。'),
('Sonar compatibility debt','DEFERRED_REAL_NEGATIVE_EVIDENCE，未提升。'),
('portability classification','runtime-source-matrix.json 对全部 16 项保留 PORTABLE / NEEDS_ADAPTER / PIPELINE_COUPLED / EXTERNAL_SYSTEM_COUPLED 分类；ZAP 是 NEEDS_ADAPTER，不把验证 wrapper 当最终插件架构。'),
('pipeline/external coupling debt','Harbor 固定 project/repo 与 robot scope；Cosign signing/trust/registry；ZAP namespace/controller/toolchain target；Dojo API/治理身份/私有前序文件；均记录，未启动最终 plugin abstraction/decoupling。'),
('display contract readiness','全部 16 条 review rows 有 source/scope/status/decision/time/evidence/fact/result 字段；blocked/missing 值保留 null，旧 receipts 时间/风险摘要缺口明确 PARTIAL；不宣称已有全量 normalized runtime result 或 Router/Loki/Grafana 接线。'),
('collector/runtime tests','114/114 PASS。'),('side-effect guard tests','49 个既有+ZAP guard 检查包含在 114 中；包括真实 wrapper 已删除 Pod/替换 UID 负向回归。'),('candidate tests','40/40 PASS，disposable checkout。'),('Policy core','5/5 PASS。'),('contract checks','10/10 PASS。'),('Regression 147/147','真实 #20 147/147 PASS，#19 也 147/147；未改 Regression 语义。'),
('Trivy tests','frozen parent differential recheck 129/129 PASS，独立临时复制；不冒称 real Harbor scan。'),
('Cosign tests','frozen parent differential recheck 268/268 PASS；不冒称新 test-key signing。'),
('ZAP tests','frozen parent 177/177 PASS；真实 #20 full stage PASS；target/wrapper guard 22 tests 在 runtime suite 内。'),
('DefectDojo tests','frozen parent differential recheck 69/69 PASS；不把 canned API tests 当本轮真实导入。'),
('completeness tests','standalone 8/8，亦包含在 runtime suite；权威兼容性累计仍 2202，不累计这些重复测试。'),
('artifact integrity tests','candidate trusted-digest/tamper/immutable-file tests PASS；native-report-identity-checks 全 match；无真实 COMPLETE artifact，不能宣称其运行完整性通过。'),
('cleanup tests','错误 UID/foreign target 拒绝；真实 #19 failed-parent 和 #20 successful-parent scanner deletion 均证实 absence；precleanup ownership/foreign/PVC checks、11对象删除和 token/workspace absence 全通过。'),
('source/hash preservation','source-preservation.json：本轮前 baseline '+str(len(before))+' files；只允许 runtime plumbing 与专用 Jenkinsfile；冻结 refs/index/r2/前轮87-file seal/owner/collector/projection/canonical manifest/V1 全核对。'),
('production V1 state','V1 active，Summary '+prod['summarySha256']+' 未变；PetClinic generation '+str(t1['deployment']['generation'])+' / revision '+t1['deployment']['revision']+' / spec hash unchanged，3/3 Ready；Argo Synced/Healthy 同 revision，3 nodes Ready。'),
('production Jenkins state','petclinic-ci #270 SUCCESS 未变，未触发 production build。'),
('validation Jenkins builds','#17 只读发现 SUCCESS；#18 binding 前置失败；#19 wrapper 清理判定失败且 old/Policy 都 FAIL；#20 正常目标扫描 SUCCESS。完整失败证据保留。'),
('release count','0（临时验证 Deployment 创建不属于生产 release）。'),('rollout count','0 production rollout；仅本轮验证目标为同 digest 的本地 transport alias 做过一次受控修改，已删除该目标。'),
('REAL_RUNTIME_FACT_CAPTURE','INCOMPLETE。'),('REAL_POLICY_OWNER','INCOMPLETE。'),('IMMUTABLE_ARTIFACT_RUNTIME','INCOMPLETE。'),('SUMMARY_V2_MIGRATION','INCOMPLETE。'),
('exact blocker if incomplete','Trivy：当前权限无法在冻结固定共享 project 证明 validation-only scan；Cosign：缺独立 test-only registry writer/admission trust 全父阶段边界；Dojo：当前用户管理 403、无已验证最小身份/cleanup 权限，且缺完整本轮原生报告链。三项停止，不强行16/16。'),
('exact next permitted action if all three runtime verdicts VERIFIED','条件尚未满足。先审查可保留 frozen Gate semantics 的独立 validation Harbor target binding/最小权限、Cosign registry+test-trust、Dojo provision+cleanup+native-chain 方案；四项 individually closed 后才运行一个真实同 run 16/16。若未来三项 runtime verdicts VERIFIED，本轮仍 STOP，不自动连接 Summary V2、不迁移 Promotion/Regression、不启用 SECURITY_ENABLED/Plugin Registry。')]
assert len(items)==73,len(items)
(O/'REPORT.md').write_text('# Final four runtime boundaries：本轮报告\n\n'+'\n\n'.join(str(i)+'. **'+k+'**\n\n   '+v for i,(k,v) in enumerate(items,1))+'\n\n```text\n'+'\n'.join(k+' = INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION'])+'\n```\n')
seal={str(p.relative_to(O)):sha(p) for p in sorted(O.rglob('*')) if p.is_file() and not p.is_symlink() and '__pycache__' not in p.parts and p.name!='artifact-sha256.json'};save('artifact-sha256.json',{'files':seal});print(json.dumps({'sealedFiles':len(seal),'reportItems':len(items),'individualWiredTotal':13,'sameRunSources':2,'blocked':3,'runtimeVerdicts':'INCOMPLETE'}))
