"""Fresh independent file/reference checks and final audit-only report."""
from pathlib import Path
from collections import Counter
import json,hashlib,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
d=read(O/'readiness.json');m=read(O/'authoritative-source-matrix.json');diff=read(O/'differential-reconciliation.json');integ=read(O/'index-integrity.json');sources=read(O/'source-integrity.json');summary=read(O/'summary-preconditions.json')
assert len(m['sources'])==18 and sum(m['counts'].values())==18
for row in integ['checks']:
 p=Path(row['path']);p=p if p.is_absolute() else R/p
 if row['directMatch']:assert p.is_file() and sha(p)==row['expected']
 else:
  assert row['resolution']=='HISTORICAL_SNAPSHOT_SUPERSEDED_WITH_EXACT_OLD_BYTES' and row['resolved']
  assert sha(R/row['archivedPath'])==row['expected'] and sha(p)==row['actual']
for row in sources['checks']:assert sha(R/row['path'])==row['expected']
for row in m['sources']:
 for n in row['productionImplementationPaths']+row['evidenceFiles']+row['evidenceIndexes']:[(R/n).is_file() or (_ for _ in ()).throw(AssertionError(n))]
 for n,h in row['sourceHashes'].items():assert sha(R/n)==h
 assert sha(R/row['classifierAdapterPath'])==row['adapterSha256']
 assert sha(R/row['policyMappingPath'])==row['policyMappingSha256']
# Check every normalized record's JSON pointer resolves to the retained original row.
for field in ['parentRecordIds','mainRecordIds','layeredRecordIds']:
 ids=diff[field];assert len(ids)==len(set(ids))
 for record in ids:
  file,pointer=record.split('#',1);obj=read(R/file)
  for bit in pointer.split('/')[1:] if pointer else []:obj=obj[int(bit)] if isinstance(obj,list) else obj[bit]
  assert isinstance(obj,dict)
assert diff['completeParentDeduplicated']['samples']==2128
assert diff['mainEvidenceWithSonarPositive']['samples']==2129
assert diff['layeredRetainedRecords']['samples']==2330
assert sum(diff['supplementaryScopes'].values())==2330-2129
assert diff['completeParentDeduplicated']['drifts']==0
assert not d['blockers'] and d['SUMMARY_INTEGRATION_READINESS']=='READY'
# Jenkins stages are re-read directly; hashes were independently checked above.
stages=[]
for n in ['Jenkinsfile','Jenkinsfile.security-audit','Jenkinsfile.candidate-build']:
 text=(R/n).read_text()
 stages.append({'path':n,'sha256':sha(R/n),'stages':[{'line':text[:x.start()].count('\n')+1,'name':x[1]} for x in re.finditer(r"stage\('([^']+)'\)",text)]})
save('jenkins-stage-crosscheck.json',{'files':stages,'authoritativeSecurityEntry':'Jenkinsfile.security-audit:33 -> securityManager(adapter=petclinic, mode=enforce) -> 14 resource-defined sources + 2 conditional provenance modules','additionalSources':'Command Analysis included before Semgrep; security approval/promotion downstream','sourceCount':18,'nonSecurityOperationalStages':'Build, resource admission, messaging, rollout, Terraform/runtime and service restore are not invented as extra scanner sources; no operational work executed','frozenInvocationScope':'Existing production security-adapter and accepted source-specific parent contracts; not all hypothetical modes/invocations or all infrastructure correctness'})
summary['localCurrentOutputExists']=(R/'.devsecops/security-summary.json').exists()
summary['localOutputNote']='No current local output file; schema is explicitly defined inline in the existing producer scripts. This audit does not generate or rewrite an output to fill this absence.'
summary['sourceLocksReferencingProducer']=['infra/security/policy/versions/promotion-baseline-v1.json','infra/security/policy/versions/regression-baseline-v1.json']
summary['futureChangeConstraint']='Additive producer work must preserve existing consumers and frozen oracles; any affected source-lock evolution needs explicit versioned reconciliation. None changed here.'
save('summary-preconditions.json',summary)
before=read(O/'before-sha256.json');changed=[n for n,h in before.items() if not (R/n).is_file() or sha(R/n)!=h];assert not changed
save('no-mutation-proof.json',{'protectedFiles':len(before),'changed':changed,'productionApiAccess':0,'newResources':0,'rollout':False,'summaryProducerModified':False,'actualSummaryModified':False,'managerOrJenkinsModified':False,'preExistingEvidenceRewritten':False,'freshIndependentShaRecheck':True,'writesOnlyInside':str(O)})
table=['| Source | Status | 完整 parent 样本 | 旧 / Policy 决策分布 |','| --- | --- | ---: | --- |']
for x in m['sources']:
 count=str(x['parentStageSampleCount']) if x['source']!='sonarqube' else '0；真实正例 1 单列'
 if x['source']=='semgrep':count+='（与 Command Analysis 共用）'
 table.append('| '+x['source']+' | '+x['latestCompatibilityStatus']+' | '+count+' | '+json.dumps(x['statistics']['oldDecisions'],ensure_ascii=False)+' |')
sections=[
 ('production source count','18。重新核对 14 个现行 adapter stage、2 个条件 provenance 插件、Command Analysis 和下游 Promotion；不是沿用旧 totals。'),
 ('complete source inventory','见下表及 authoritative-source-matrix.json；每行包含生产 stage/entry、实现与 adapter 路径、Policy mapping、源码 SHA、最新状态和证据索引。'),
 ('VERIFIED count','17'),('DEFERRED count','1（Sonar）'),('ENVIRONMENT_BLOCKED count','0'),('NOT_TESTED count','0 个未解释的生产来源；Sonar 真实负例子路径仍为 NOT_TESTED，不改称 VERIFIED。'),('FAILED count','0'),
 ('SOPS final status','VERIFIED。12 个 REAL_CONTROLLED_EXECUTION；旧 Gate/Policy 各 12；MATCH 12、DRIFT 0；88 文件 final index 与当前冻结 Gate/adapter/Policy/guard 哈希核对通过；raw fact、生产访问 0、cleanup 证据俱在。'),
 ('Sonar final status','DEFERRED。真实 positive VERIFIED；real negative NOT_TESTED / DEFERRED_REAL_NEGATIVE_EVIDENCE；synthetic ERROR 仅逻辑测试。task→analysis→condition 真实正例存在；与 #270 的关联为 workspace/time correlation，并非逐构建直接 task 归档。按既定延期规则，此历史补证债不单独阻断 metadata 集成。没有新增 Sonar run。'),
 ('per-source parent-stage sample counts','见完整来源表；Semgrep 与 Command Analysis 共用 136 条，只计一次。Sonar 的 1 个正例不是完整 parent 证明。Trivy release-scan 20 与 DB prerequisite 41 单列辅助层。'),
 ('authoritative deduplicated sample total','2128 个完整 parent 样本；不是 18 行简单求和，也不是累计 Policy tests。'),
 ('total MATCH','2128 个 parent MATCH；加入 Sonar 已验正例后 main evidence 为 2129 MATCH。'),('total DRIFT','0；分层保留的 2330 条记录同样为 0。'),
 ('old-decision distribution',json.dumps(diff['completeParentDeduplicated']['oldDecisions'],ensure_ascii=False)+'；SKIPPED/NOT_CONFIGURED 是保留的 null-decision 状态，没有转成 PASS。'),
 ('Policy-decision distribution',json.dumps(diff['completeParentDeduplicated']['policyDecisions'],ensure_ascii=False)+'；与旧结果一致。'),
 ('main evidence total','2129＝去重 parent 2128＋Sonar 真实正例 1。'),
 ('layered evidence total','2330＝main 2129＋辅助层 201。辅助层＝Trivy release20＋DB41＋旧 Kyverno child49＋旧 Command child5＋旧 contracts39＋SOPS unit20＋Gitleaks classifier7＋原 classifier 重核20。它们不提升 parent 样本数。索引重复引用不计作新执行。'),
 ('evidence index count',str(integ['indexCount'])+' 个既有选定索引；本轮自身最终索引另存，不混入该数。'),
 ('evidence hash/reference validation',str(integ['hashReferences'])+' 条引用；直接匹配 '+str(integ['directMatches'])+'，另 2 条旧 guard 历史快照按原始 .before 字节及明确修改收据核验恢复可追溯性；未改写旧索引、未隐藏 mismatch。未解决失败 0。共 '+str(integ['uniqueReferencedFiles'])+' 个不同引用文件。'),
 ('source hash validation',str(sources['references'])+' 条冻结源码引用、'+str(sources['uniqueFiles'])+' 个不同文件，全部匹配。各 adapter 另与 SOPS 前权威快照复核。'),
 ('Policy core validation status','VERIFIED（readiness 范围）：既有核心 tests 5/5；只读 contract checks 10/10；版本、默认 standard、显式 low、strict、分层 override、POLICY_ERROR 及 raw 保持均通过。override 来源现由 appliedOverrides[].layer 等提供，当前没有字面 overrideSource 字段；下一轮需追加映射，不能声称已写入 Summary。'),
 ('Summary producer location','生产：infra/security/security-summary.mjs，由 Jenkinsfile.security-audit:48/:75 调用；generic：resources/security-manager/summary.mjs，经 vars/securityManager.groovy 的 libraryResource 使用；infra/security/manager/summary.mjs 是内容相同的仓库副本。'),
 ('current summary schema location','schema:1 位于三个 producer 的内联对象定义；输出为 .devsecops/security-summary.json；没有独立 JSON Schema 文件，也没有本地当前 run 的输出文件。本轮未生成任何替代 Summary。'),
 ('downstream consumers','promotion/evidence.mjs → promotion/contract.mjs → sign-approve.mjs / promote.mjs；Jenkins archive；Loki sink；Grafana governance panels 的 JSON 查询定义。只识别消费关系，未执行 publish/query。Dojo 当前仍直接依赖 scanner 私有文件，不冒充 Summary consumer。'),
 ('remaining deferred debt','Sonar 真实负例 build→task→analysis→ERROR→conditions 直接绑定；正例逐构建 task 归档。其他 controlled replay 的历史完整 CLI/live 环境证明保留范围限制；不宣称历史上发生全部负例。'),
 ('remaining later architecture work','统一插件契约、SECURITY_ENABLED、独立禁用/capability 隔离、Provenance opt-in、DefectDojo 解耦、Result Router、Loki/Grafana query closure、portability smoke。按既定顺序留后，未豁免或实现。'),
 ('actual Summary integration blockers','无。Policy compatibility core 与 SOPS blocker 为 CLOSED_FOR_SUMMARY_INTEGRATION；统一插件契约/Dojo 解耦/Result closure 为 STILL_LATER_ARCHITECTURE_WORK。'),
 ('SUMMARY_INTEGRATION_READINESS','READY'),('exact blocker if NOT_READY','不适用；无未解决的 source/evidence/hash/compatibility blocker。'),
 ('exact next permitted action if READY','STOP。下一轮可单独限定为：现有 Summary producer 追加兼容 Policy metadata，并验证既有 schema 字段与消费者；保持 Gate 和发布行为不变。当前不实施，不自动启动插件契约、解耦或 Router。')]
assert len(sections)==30
text='SUMMARY_INTEGRATION_READINESS =\nREADY\n\n本轮仅进行仓库与既有证据审计；不代表实际 Summary 集成已完成。\n\n'
text+='\n\n'.join(f'{i}. **{name}**：{value}' for i,(name,value) in enumerate(sections,1))
text+='\n\n'+'\n'.join(table)+'\n\n兼容性边界：A＝冻结当前生产行为的兼容证明；B＝一般产品/安全正确性；C＝在线生产验证。这里只满足 A 的既定 readiness 范围，不宣称 B、C、SLSA 认证或全量历史负例。CONTROLLED_REPLAY/完整父阶段受控样本与 classifier-only 单元样本分开计数；SOPS 是真实隔离受控执行，不是生产事故。\n\n只读核验范围：既有 2026-11-01/02 artifact/evidence/implementation 哈希索引、所选历史 parent 索引、最新 SOPS baseline/precleanup/final 索引、全部 Policy source locks。不同目录的准备期 project-before 快照不是额外差分样本；旧 frozen verdict 作为历史保留，由本轮权威矩阵替代当前状态。\n\n两条历史 guard 索引的处理：旧文件路径与当前已批准版本不同；旧字节在 sops-preparation-blocker-closure/*.before 中仍精确匹配旧 SHA，protected-after.json 明确记录预期改动，新版 source-sha256 与 SOPS authoritative freeze 匹配。因此是已解释的版本替换，不是未解释源码漂移。原始索引和来源文件均未改写。\n\n审计脚本首次只在 historical/ 子目录查找 Regression excerpt；随后按既有 artifact 索引定位到根目录 historical-270-regression.log，精确 SHA 匹配。仅修正审计定位，没有补造证据或更改任何既有结果。\n\n证据入口：readiness.json、authoritative-source-matrix.json、differential-reconciliation.json、index-integrity.json、source-integrity.json、summary-preconditions.json、blocker-disposition.json、no-mutation-proof.json、artifact-sha256.json、final-validation.json。\n'
(O/'REPORT.md').write_text(text)
files={str(p.relative_to(O)):sha(p) for p in O.rglob('*') if p.is_file() and p.name not in ['artifact-sha256.json','final-validation.json']}
save('artifact-sha256.json',files)
assert all((O/n).is_file() and sha(O/n)==h for n,h in files.items())
save('final-validation.json',{'status':'PASS','SUMMARY_INTEGRATION_READINESS':'READY','auditArtifactFiles':len(files),'auditIndexSha256':sha(O/'artifact-sha256.json'),'preExistingProjectFilesUnchanged':len(before),'existingEvidenceIndexes':integ['indexCount'],'existingHashReferences':integ['hashReferences'],'directMatches':integ['directMatches'],'historicalSupersessionResolutions':2,'unresolvedReferenceFailures':0,'recordPointersValidated':True,'sourceHashesRecheckedFresh':True,'summaryOrProducerModified':False,'productionAccess':0,'liveGateOrScannerRuns':0,'rollout':False,'nextStageStarted':False})
print('SUMMARY_INTEGRATION_READINESS =\nREADY\nFINAL_AUDIT_INDEX_PASS; STOP')
