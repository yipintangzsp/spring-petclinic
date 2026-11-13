"""Seal scoped partial runtime proof. Never changes frozen evidence or Summary."""
from pathlib import Path
import hashlib,json,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
load=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
before=load(O/'before-sha256.json')
changed=[p for p,h in before.items() if not (R/p).is_file() or sha(R/p)!=h]
allowed=lambda p:p=='Jenkinsfile.runtime-facts' or p.startswith('infra/security/runtime-facts/')
assert all(allowed(p) for p in changed),changed
authority=R/'evidence/2026-11-02/summary-integration-readiness-recheck'
refs=load(authority/'source-integrity.json')['checks'];assert all(sha(R/x['path'])==x['expected'] for x in refs)
indices=load(authority/'index-integrity.json')['checks']
for x in indices:
 p=Path(x['path']);p=p if p.is_absolute() else R/p
 if x['directMatch']:assert sha(p)==x['expected']
 else:assert x['resolved'] and sha(R/x['archivedPath'])==x['expected'] and sha(p)==x['actual']
contract=load(R/'infra/security/summary-v2/candidate-integrity-r2.json')
assert all(sha(R/p)==h for v in contract['versions'].values() for p,h in v['files'].items())
bundle=load(O/'build-9-runtime-source-bundle.json')
generated=set(bundle['generatedGitMetadataFiles'])|{'runtime-sbom-clean-source.tar.gz','runtime-sbom-clean-source.json','runtime-sonar-origin.json'}
assert all(p in generated or sha(R/p)==h for p,h in bundle['files'].items())
build=load(O/'jenkins-build-9.json');assert build['build']==9 and not build['building'] and build['result']=='FAILURE'
assert build['definitionSha256']==sha(R/'Jenkinsfile.runtime-facts')==bundle['files']['Jenkinsfile.runtime-facts']
artifacts=build['artifacts']
artifact=lambda suffix:next(v for p,v in artifacts.items() if p.endswith('/'+suffix))
coverage=artifact('coverage.json');assert coverage['failures']==[] and coverage['complete'] is False
captured=[s for s in coverage['sources'] if s['state']=='CAPTURED'];assert len(captured)==8 and len(coverage['missing'])==8
original5=['regression','falco-baseline','falco-final','kyverno','kubescape']
for row in captured:
 name=row['sourceId'];result=artifact(name+'.result.json');capture=artifact(name+'.capture.json');gate=coverage['gate'][name]
 assert row['evaluationCount']==capture['evaluationCount']==1
 assert row['resultDigest']==result['resultDigest']==capture['resultDigest']==gate['resultDigest']
 assert result['binding']==coverage['binding'] and result['rawFactDigest']==capture['rawFactDigest'] and result['evidenceComplete']
 assert capture['rawPayloadPersisted'] is False
 if name in original5+['sbom']:assert gate['decision']==result['result']['decision']=='PASS' and capture['execution']['exitStatus']==0
 else:
  assert result['result']['decision'] is None and result['result']['status']==gate['status']=='SKIPPED'
  assert capture['execution']['kind']=='JENKINS_CPS_FUNCTION' and capture['execution']['exitStatus'] is None and capture['execution']['returnStatus']=='RETURNED'
 if name.startswith('falco'):
  from datetime import datetime
  windows=capture['evidence'][0]['sampleWindows'];assert windows
  for w in windows:
   assert w['windowEndMs']-w['windowStartMs']==15000
   assert w['windowEndMs']<=w['startedAtMs']<=w['logCompletedAtMs']<=w['completedAtMs']
   assert int(datetime.fromisoformat(w['querySince'].replace('Z','+00:00')).timestamp()*1000)==w['windowStartMs']
assert all(s['evaluationCount'] is None and s['resultDigest'] is None for s in coverage['sources'] if s['state']=='NOT_OBSERVED')
assert coverage['artifactGenerated'] is False and 'incomplete' in coverage['artifactRejection']
assert not any('pre-approval-' in p for p in artifacts)
checks_after=[]
for number,expected in [(5,5),(6,6),(7,7),(8,8),(9,8)]:
 b=load(O/('jenkins-baseline-build-5.json' if number==5 else 'jenkins-build-'+str(number)+'.json'))
 c=next(v for p,v in b['artifacts'].items() if p.endswith('/coverage.json'))
 assert sum(s['state']=='CAPTURED' for s in c['sources'])==expected and not c['failures']
 for source in original5:
  row=next(s for s in c['sources'] if s['sourceId']==source)
  assert row['evaluationCount']==1 and row['resultDigest']==c['gate'][source]['resultDigest'] and c['gate'][source]['decision']=='PASS'
 counts=b['regression'][0]['counts'];assert counts['tests']==counts['pass']==147 and counts['fail']==0
 checks_after.append({'build':number,'captured':expected,'originalFive':'PASS','regression':counts,'gateReuse':'MATCH','collectorErrors':0})
save('baseline-after-each-source.json',checks_after)
clean=artifact('sbom-build-input.json');assert clean['cleanupComplete'] and clean['commit']==coverage['binding']['source']
sonar=artifact('sonar-readonly-observation.json');assert sonar['status']=='OBSERVED_EXISTING_ANALYSIS_ONLY'
assert len(sonar['requests'])==2 and all(q['method']=='GET' and q['httpStatus']==200 for q in sonar['requests'])
assert sonar['policyEvaluations']==sonar['newAnalysis']==0 and sonar['raw']['gate']['projectStatus']['status']=='OK'
assert sonar['origin']['source']!=coverage['binding']['source'] and sonar['origin']['auditTargetImage']!=coverage['binding']['candidate']
save('sonar-runtime-boundary.json',{'observation':sonar,'canonicalOwnerAdmission':'NOT_OBSERVED','reason':'Historical source/audit target differs from current collector source/runtime candidate; direct per-build task archive missing. No lineage exemption introduced.','negativeCompatibility':'DEFERRED_REAL_NEGATIVE_EVIDENCE','privilegeExpansion':False,'credentialExported':False})
def tap(file,expected):
 text=(O/file).read_text();stats={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',text,re.M)}
 assert stats['tests']==stats['pass']==expected and all(stats[k]==0 for k in ['fail','cancelled','skipped','todo'])
 return {**stats,'path':file,'sha256':sha(O/file)}
checks={'collectorOwnerAndSourceSpecific':tap('collector-source-tests-final.log',39),'candidate':tap('candidate-tests.log',40),'policyCore':tap('policy-core.log',5),'regression':build['regression'][0]}
checks['policyContracts']=load(O/'policy-contract.json');assert checks['policyContracts']['ready'] and len(checks['policyContracts']['checks'])==10
replay=load(O/'source-replay-results.json');assert replay['falco']['samples']==replay['falco']['match']==4 and replay['falco']['drift']==0
assert replay['sops']['shapes']==3 and replay['sops']['productionSecretAccess']==0
live=load(O/'live-jenkins-baseline.json');old=load(R/'evidence/2026-11-02/runtime-facts-owner/live-jenkins-baseline.json')
prod=next(j for j in live['jobs'] if j['job']=='petclinic-ci');prior=next(j for j in old['jobs'] if j['job']=='petclinic-ci')
for k in ['latestBuild','result','scriptPath','summarySha256','checkoutRevisions']:assert prod[k]==prior[k],k
assert load(O/'live-workspace-hashes.json')==load(R/'evidence/2026-11-02/runtime-facts-owner/live-workspace-hashes.json')
post=load(O/'node-lease-postflight.json');assert post['lease']['validationHolderReleased']
assert all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in post['nodes'])
leaks=[];scanned=[]
patterns=[r'AGE-SECRET-KEY-1[A-Z0-9]{40,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'"token"\s*:\s*"eyJ[A-Za-z0-9_.-]{80,}']
for p in O.rglob('*'):
 if p.is_file() and not p.is_symlink() and p.suffix in ['.json','.log']:
  t=p.read_text(errors='replace');scanned.append(str(p.relative_to(O)))
  if any(re.search(pattern,t) for pattern in patterns):leaks.append(str(p.relative_to(O)))
assert not leaks,leaks
save('secret-leakage-check.json',{'classification':'PATTERN_SCAN_AND_DATA_MINIMIZATION_NOT_UNIVERSAL_LEAK_PROOF','files':scanned,'matches':leaks,'productionSopsGateExecutions':0,'productionSecretOrAgeKeyAccess':0,'sonarCredentialExported':False,'rawScannerPayloadsPersisted':False})
save('source-preservation.json',{'preexistingBaselineFiles':len(before),'unchangedProtectedFiles':len(before)-len(changed),'approvedCollectorFilesChanged':changed,'unauthorizedChanges':[],'frozenSourceRefs':len(refs),'distinctFrozenSourcePaths':len({x['path'] for x in refs}),'priorIndexRefs':len(indices),'r2Unchanged':True,'bundleFiles':len(bundle['files']),'generatedSourceFiles':sorted(generated),'productionWorkspaceUnchanged':True,'productionJob':{k:prod[k] for k in ['job','latestBuild','result','summarySha256']}})
save('test-results.json',checks)
inventory=load(O/'remaining-source-inventory.json');assert inventory['remaining']==11
plan=load(R/'resources/security-manager/petclinic-adapter.json')
contracts=[]
for row in coverage['sources']:
 name=row['sourceId'];p=next((m for m in plan if ('semgrep-command-audit' if m['id']=='semgrep' else m['id'])==name),None)
 source=next((s for s in inventory['sources'] if s['sourceId']==name),{})
 observed=name in coverage['gate'];scope='FULL_ORIGINAL_EXECUTED_BRANCH' if observed else 'NOT_OBSERVED'
 if name in ['provenance','build-provenance']:scope='ACTUAL_DEFAULT_UNENABLED_RETURN_ONLY_NO_ENABLED_ATTESTATION_COVERAGE'
 contracts.append({**row,'factProducer':p['command'] if p else source.get('actualCommandOrFunction'),'scope':scope,'collectorMapping':('helper-return.mjs' if name in ['provenance','build-provenance'] else 'sbom-execute.mjs + sbom-observer.mjs' if name=='sbom' else 'execute.mjs + source-specific observer') if observed else None,'adapterInput':'facts.raw; bytes and source-specific observations unchanged' if observed else None,'gateConsumedFields':'ResolvedPolicyResult decision/status/resultDigest; no evaluator' if observed else None,'policyResult':coverage['gate'].get(name),'factCompleteness':'COMPLETE_FOR_OBSERVED_BRANCH' if observed else 'FACT_CONTRACT_INCOMPLETE','riskGroup':source.get('group','PREVIOUSLY_APPROVED_BASELINE'),'blocker':None if observed else source.get('currentBlocker'),'missingEvidence':None if observed else source.get('requiredRawFacts')})
save('source-fact-contracts.json',{'canonicalCount':16,'sameRunCaptured':8,'missing':coverage['missing'],'sources':contracts,'note':'Actual default SKIPPED preserves helper semantics; it is not evidence of enabled DSSE/signing/registry verification. No frozen production coverage status is upgraded.'})
save('runtime-source-coverage.json',coverage)
blockers=[{'id':'EXTERNAL_WRITE_BOUNDARY','sources':['gitleaks','semgrep-command-audit','trivy','cosign','zap','defectdojo'],'status':'FACT_CONTRACT_INCOMPLETE / RUNTIME_OBSERVATION_BLOCKED','evidence':'remaining-source-inventory.json; reviewed original stages create scanner Pods / POST scan / sign/push / Dojo import/PATCH. Pre-write boundary lacks full scanner/import/cleanup/verification outcomes. No direct write path executed.','minimalFix':'Attach passive collection at a complete, already-authorized actual stage boundary; or separately review an isolated controlled execution and ephemeral fact transport. Read-only success summaries cannot substitute.'},
 {'id':'SOPS_ISOLATION','sources':['sops'],'status':'RUNTIME_OBSERVATION_BLOCKED','evidence':'Prior private fixture removed; only redacted archive shapes remain. Fresh MIN_RBAC guard/tool/key/input context and same-owner secure transport are not available in this dedicated Jenkins run.','minimalFix':'Re-establish the specifically approved isolated fixture/executor path and collect fresh positive/decrypt/prerequisite facts without production Secret/key access; never reconstruct plaintext from hashes.'},
 {'id':'SONAR_LINEAGE','sources':['sonarqube'],'status':'FACT_CONTRACT_INCOMPLETE','evidence':'Current authorized exact-task/exact-analysis GETs both 200, Gate OK, but origin #270 source/audit candidate differs from current bound source/runtime candidate; direct archived build-task binding NOT_TESTED. Anonymous 401 did not trigger a privilege escalation.','minimalFix':'Provide a current-candidate/source-verifiable analysis association, then feed unchanged real facts into the sole owner. Preserve real negative DEFERRED status; no new production analysis merely for proof.'},
 {'id':'ENABLED_HELPER_SCOPE','sources':['provenance','build-provenance'],'status':'ENABLED_BRANCH_NOT_OBSERVED','evidence':'Original frozen helpers really returned SKIPPED for empty configuration. No attestation/signing/registry branch executed. Historical #270 enabled success is not copied into this run.','minimalFix':'If enabled-branch runtime proof is required, supply complete read-only current-candidate verification facts under the authorized identity; never enable signing/push for collection.'},
 {'id':'FULL_ARTIFACT_INPUTS','status':'NOT_READY','evidence':'Only 8/16 source receipts; candidate writer correctly rejects completeness. Full aggregate external checks / V1 projection / r2 producer inputs not wired to a complete live set.','minimalFix':'After complete source capture and reuse proof, wire real bound artifact producer and aggregation inputs. No synthetic completion or Summary activation.'}]
verdict={k:'INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']}
verdict.update({'canonical':16,'previouslyWired':5,'newlyWired':['sbom','provenance','build-provenance'],'sameRunCaptured':8,'missing':coverage['missing'],'blockers':blockers,'productionBuildsTriggered':0,'validationBuildsThisIteration':5,'validationBuildsLifetime':9,'release':0,'rollout':0,'approval':0,'promotion':0,'summaryActivated':False})
save('verdict.json',verdict)
identities='；'.join(s['sourceId']+'='+s['resultDigest'] for s in captured)
items=[
 ('canonical runtime source count','16；来自 canonical registry，18 compatibility labels 中 Semgrep 为 alias，Promotion 为 post-approval。'),
 ('previously wired source count','5。'),('remaining source count before this iteration','11。'),
 ('remaining-source inventory','remaining-source-inventory.json：由 registry、生产 plan、原 Shared Library helper 和前轮真实 coverage 重建；逐项包含命令、路径、依赖、权限、副作用、adapter 与缺失事实。'),
 ('risk grouping','A: '+', '.join(inventory['groups']['A'])+'；B: '+', '.join(inventory['groups']['B'])+'；C: '+', '.join(inventory['groups']['C'])+'。分类先于执行；C 默认返回与正常写分支分别审查。'),
 ('newly wired sources','SBOM 原 Maven+verifier；Provenance 和 Build Provenance 冻结原函数的实际默认 SKIPPED 返回。未宣称 enabled branch 已覆盖。'),
 ('total wired sources','专用真实 Jenkins #9 中 8/16；6 PASS，2 explicit SKIPPED。'),
 ('still-unobserved sources',', '.join(coverage['missing'])+'；仍 NOT_OBSERVED，未补默认状态。'),
 ('per-source fact producer','详见 source-fact-contracts.json。原五项保持原命令；SBOM 从精确 tracked HEAD 临时 checkout 执行原命令；两 helper 核对冻结源码 hash/library commit 后真实调用。'),
 ('per-source collector mapping','source-fact-contracts.json；原始 source-specific payload 保留于内存 facts.raw，receipt 只存 digest/安全元数据。SBOM 保留真实生成器退出、unzip bytes、Maven bytes、原报告写入与源码输入身份。'),
 ('per-source evaluation counts','8 个已接入来源各 1；另 8 个 null，不能视作已求值。Sonar 额外只读观察为 0 次 Policy 求值。'),
 ('duplicate-evaluation result','39 项测试覆盖重复 source、并发、第二 owner 与 Gate 重复 handoff；第二次求值前拒绝。真实 #9 每项 claim/receipt 一份。'),
 ('per-source result IDs',identities),
 ('Gate reuse result','8 项 capture/result/gate/coverage 的 resultDigest 完全一致；实际 CPS 返回用真实 RETURNED + exitStatus=null，不捏造进程 exit 0。'),
 ('sources with complete facts','原五项、SBOM 执行分支，以及两个 helper 的默认未启用分支。此处不代表两个 helper 的 enabled attestation branch。'),
 ('sources with incomplete facts',', '.join(coverage['missing'])+'。缺少真实扫描/导入/清理/隔离/分析血缘证据；source-fact-contracts.json 不把 shell success 提升为完整 wrapper facts。'),
 ('read-only credential-bound sources','Sonar 使用现有 Jenkins sonar-token 仅 GET 已知 task 与 exact analysis；不导出 token、不查凭据存储、不重试已知受限 history API。Build Provenance 默认分支不读取 Harbor 凭据；启用 verify 分支未验证。'),
 ('external-write-risk sources','Gitleaks/Semgrep/ZAP 创建临时扫描 Pod；Trivy POST scan/候选拷贝；Cosign/Provenance sign/push；Dojo POST/PATCH；SOPS 只限专用隔离夹具。均未为证明 collector 而直接运行写分支。'),
 ('Sonar runtime status','真实已有 task/analysis GET 200/200，Quality Gate OK；当前源码/候选血缘未证明，因此没有 owner receipt，不把旧结果重绑定本轮。真实负例仍 DEFERRED_REAL_NEGATIVE_EVIDENCE。'),
 ('SOPS runtime boundary','CONTROLLED_ISOLATED_RUNTIME 边界保留；原隔离夹具已清理，本轮新 SOPS 执行 0。正向/decrypt/tool-missing 3 类脱敏历史 shape 保持映射；未重新求值脱敏正例，未恢复或打印 plaintext。生产 Secret/key 访问 0。'),
 ('DefectDojo runtime boundary','完整父阶段需真实 import/Test/reimport/dedupe/queryback/API observations；只读预查询不能提供未执行写操作的结果。未新导入/PATCH，未解耦私有文件依赖。'),
 ('Promotion/pre-approval boundary','Promotion 不在 canonical preapproval 16 项中；没有 future PromotionResult/self-approval；Promotion 与 Regression 生产逻辑均未迁移。'),
 ('Falco normal result','#9 baseline/final 原命令均 PASS；once/same receipt。每个真实查询窗口保留 observed since-time + 15000ms，无固定延迟推导。'),
 ('Falco 2-second result','accepted whole-Gate controlled replay 4 MATCH/0 DRIFT，baseline/final 两个 2 秒边界均 old FAIL = Policy FAIL，same receipt。不是本轮线上故障。'),
 ('Regression 147/147','本轮专用 #5/#6/#7/#8/#9 均实际运行原命令，147/147、0 fail/skip/todo/cancel。等价事实 result identity 稳定由隔离确定性测试验证；不同 build 的 digest 不应相同。'),
 ('collector/owner tests','39/39 PASS（含 source-specific）；旧五项基线在每次新增来源后重跑，见 baseline-after-each-source.json。'),
 ('candidate tests','40/40 PASS；unchanged 候选测试在临时 checkout 执行，旧 accepted evidence 未改。这不是 COMPLETE runtime artifact 证据。'),
 ('Policy core','5/5 PASS。'),('contract checks','10/10 PASS；默认 standard/显式 low/strict/override/POLICY_ERROR 保持。'),
 ('source-specific tests','SBOM 4 项 unit（3 项 old-vs-Policy differential）、clean checkout 2 项、原 helper return 9 项、Sonar read-only 3 项及原五项 observer/owner 回归均在 39 项内。单元夹具不是新生产兼容性样本。真实 SBOM #6–#8 FAIL/FAIL，#9 PASS/PASS；真实 helper defaults 在 #7/#8/#9 观察。'),
 ('canonical completeness result','INCOMPLETE：8/16；#9 missing-source rejection 实际执行，未放宽完整性。'),
 ('immutable artifact status','NOT_GENERATED；partial receipt bundle 不称 COMPLETE artifact。'),
 ('artifact identity/hash','无 COMPLETE runtime artifact，identity/hash NOT_APPLICABLE；当前 input bundle SHA256 '+sha(O/'build-9-nonrelease-source.tar.gz')+'，不能用它冒充最终 artifact hash。'),
 ('candidate/build binding',json.dumps(coverage['binding'],ensure_ascii=False)+'；667 文件 bundle hash + 精确 tracked build checkout hash；每个已接入 receipt 与同一 binding 一致。Sonar 旧目标未混入。'),
 ('aggregate Gate result','INCOMPLETE；8 项 per-source Gate reuse MATCH，不宣称全量 aggregate 已验证。专用 Jenkins #9 FAILURE，原 source decision 和缺项拒绝均保留；生产 job 未执行。'),
 ('source hash preservation',str(len(before))+' 个旧文件基线；仅 '+str(len(changed))+' 个允许的 collector/专用 pipeline 文件变更；'+str(len(refs))+' frozen refs / '+str(len({x['path'] for x in refs}))+' distinct 路径、'+str(len(indices))+' prior index refs 与 r2 hash 全匹配。'),
 ('V1 active path unchanged','YES。petclinic-ci #270 SUCCESS，V1 Summary SHA '+prod['summarySha256']+'；实时生产 workspace hash 与前轮逐项一致。'),
 ('production Jenkins build count','本轮触发 0；最新仍 #270。'),
 ('validation Jenkins build count','本轮 #5–#9 共 5 次；专用 job 累计 9 次。#5 baseline；#6 SBOM 实际失败事实；#7 Provenance default；#8 Build Provenance default；#9 clean SBOM + Sonar 只读取证 + 八项回归。定义上传前 Groovy 引号错误已修正，未因此创建构建或修改生产 job。'),
 ('release count','0。'),('rollout count','0。'),
 ('REAL_RUNTIME_FACT_CAPTURE','INCOMPLETE。'),('REAL_POLICY_OWNER','INCOMPLETE。'),('IMMUTABLE_ARTIFACT_RUNTIME','INCOMPLETE。'),('SUMMARY_V2_MIGRATION','INCOMPLETE。'),
 ('exact remaining blocker','verdict.json 五类 blocker：6 项外部写边界后完整事实缺失、SOPS 新隔离事实/transport 缺失、Sonar 当前候选血缘缺失、两个 optional helper enabled scope 未观察、全量 artifact producer/aggregate 输入未接线。本轮无权限升级，无 COMPLETE 伪造。'),
 ('exact next permitted action if all three runtime verdicts VERIFIED','当前未满足，不能进入 Summary。只能继续审查/补齐本阶段上述事实边界；需要新写操作或隔离 transport 时先明确对应授权范围。即使未来三项 VERIFIED，本附件仍要求 STOP，不能自动接 Summary V2。')]
assert len(items)==47
report=['# Runtime remaining sources — 本轮结果','', '真实专用 Jenkins #9 捕获 8/16 来源；本轮新增 3 项接线，其中两个只覆盖原 helper 的默认未启用分支。整体 INCOMPLETE，未生成 COMPLETE artifact，未激活 Summary V2。','',
 '更正：早先进度中“#6 SBOM 已通过”不准确。原始日志与归档证明 #6–#8 的 Maven NoHttp 检查失败，old Gate 与 Policy 同为 FAIL。#9 从精确 tracked HEAD 临时 checkout 构建，全部原检查及 verifier 才实际 PASS；没有跳过检查、改 Gate 或修改生产代码。','',
 '证据类别严格区分：REAL_DEDICATED_NONRELEASE_JENKINS_EXECUTION、REAL_JENKINS_CPS_DEFAULT_RETURN、REAL_READ_ONLY_EXISTING_ANALYSIS_OBSERVATION、CONTROLLED_ACCEPTED_GATE_REPLAY、HISTORICAL_CONTROLLED_EXECUTION_REDACTED_SHAPE_ONLY、SYNTHETIC_UNIT_ONLY。','']
for i,(title,content) in enumerate(items,1):report.extend([f'{i}. **{title}** — {content}',''])
report.extend(['```text','REAL_RUNTIME_FACT_CAPTURE =','INCOMPLETE','REAL_POLICY_OWNER =','INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME =','INCOMPLETE','SUMMARY_V2_MIGRATION =','INCOMPLETE','```','','已停止本阶段。节点均 Ready，临时 heavy Lease 已释放；没有新常驻组件或扫描 Pod，干净 SBOM checkout 已删除。'])
(O/'REPORT.md').write_text('\n'.join(report)+'\n')
doc=R/'docs/RUNTIME-REMAINING-SOURCES-20261102.md';assert not doc.exists();doc.write_text('\n'.join(report)+'\n')
save('artifact-sha256.json',{str(p.relative_to(O)):sha(p) for p in O.rglob('*') if p.is_file() and not p.is_symlink() and p.name!='artifact-sha256.json'})
print(json.dumps({'captured':8,'expected':16,'collectorTests':39,'candidateTests':40,'core':5,'contracts':10,'regression':147,'protectedUnchanged':len(before)-len(changed),'reportItems':len(items),'markers':{k:verdict[k] for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']},'release':0,'rollout':0}))
