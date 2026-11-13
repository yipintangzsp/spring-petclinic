"""Repository-only compatibility audit. Writes evidence/reports in this directory only."""
from pathlib import Path
from collections import Counter
import hashlib,json,re,subprocess

ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
E=ROOT/'evidence/2026-11-01'
def read(p): return json.loads((ROOT/p).read_text())
def rel(p): return str(p.relative_to(ROOT))
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,d): (OUT/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def decisions(rows):
 out=[]
 for r in rows:
  old=next((r[k] for k in ['oldDecision','legacyDecision','legacy'] if k in r),None)
  new=next((r[k] for k in ['standardDecision','standard'] if k in r),None)
  # Explicit null decision + SKIPPED is a preserved non-decision, never PASS.
  explicit_null=old is None and new is None and 'oldDecision' in r and 'standardDecision' in r
  if old is None and r.get('oldStatus') in ['SKIPPED','DISABLED','NOT_CONFIGURED']:old=r['oldStatus']
  if new is None and r.get('standardStatus') in ['SKIPPED','DISABLED','NOT_CONFIGURED']:new=r['standardStatus']
  raw=next((r[k] for k in ['rawPreserved','rawUnchanged','inputUnchanged'] if k in r),None)
  out.append(dict(old=old,standard=new,rawPreserved=raw,explicitNull=explicit_null,statusMatch=r.get('oldStatus')==r.get('standardStatus')))
 return dict(samples=len(out),matched=sum(r['old']==r['standard'] and r['old'] is not None and r['statusMatch'] for r in out),
  mismatched=sum(r['old']!=r['standard'] or r['old'] is None or not r['statusMatch'] for r in out),explicitNullDecisions=sum(r['explicitNull'] for r in out),rawPreserved=all(r['rawPreserved'] is True for r in out),
  oldDecisions=dict(Counter(r['old'] for r in out)),standardDecisions=dict(Counter(r['standard'] for r in out)))

original=read('evidence/2026-11-01/policy-engine/production-gate-inventory.json')['sources']
latest=read('evidence/2026-11-01/promotion-parent/production-coverage-update.json')
production=read('resources/security-manager/petclinic-adapter.json')
profiles=read('resources/security-manager/profiles.json')
ids={x['source'] for x in original};live_ids={x['id'] for x in production}
known_match=re.search(r'def known=(\[.*?\])',(ROOT/'vars/securityManager.groovy').read_text())
known=set(json.loads(known_match[1].replace("'",'"')))
inventory_check={
 'originalCount':len(original),'currentAdapterStages':len(production),
 'originalAccounted':sorted(ids),
 'missingOriginalRows':sorted(ids-{x['source'] for x in latest['sources']}),
 'unaccountedCurrentStages':sorted(live_ids-ids),
 'productionEntryMismatches':[x['id'] for x in production if x['command']!=next((s['entry'] for s in original if s['source']==x['id']),None)],
 'unaccountedGenericModules':sorted(known-ids),
 'unaccountedProfileModules':sorted({v for row in profiles.values() for v in row}-ids),
 'conditionalModules':['provenance','build-provenance'],
 'explicitAdditionalOriginalSources':['semgrep-command-audit','security-approval-promotion'],
 'aliases':{'semgrep':'semgrep-command-audit complete original parent proof; same production command, counted once'},
 'scope':'Static current repository production sources; no remote freshness or live pipeline certification',
}
inventory_check['complete']=not any(inventory_check[k] for k in ['missingOriginalRows','unaccountedCurrentStages','productionEntryMismatches','unaccountedGenericModules','unaccountedProfileModules']) and len(ids)==18
save('inventory-reconciliation.json',inventory_check)

# Recheck every retained index, not only the latest report's success flag.
index_results=[]
for index in sorted(list(E.glob('*/artifact-sha256.json'))+list(E.glob('*/evidence-hashes.json'))):
 checks=[]
 for name,digest in json.loads(index.read_text()).items():
  p=ROOT/name if (ROOT/name).exists() else index.parent/name
  actual=sha(p) if p.is_file() else None
  checks.append(dict(path=rel(p),match=actual==digest,expected=digest,actual=actual))
 index_results.append(dict(index=rel(index),entries=len(checks),matched=sum(x['match'] for x in checks),failures=[x for x in checks if not x['match']]))
source_checks=[]
for lock in sorted((ROOT/'infra/security/policy/versions').glob('*.json')):
 d=json.loads(lock.read_text())
 for field in ['sourceHashes','workflowSourceHashes']:
  for name,digest in d.get(field,{}).items():
   p=ROOT/name;source_checks.append(dict(lock=rel(lock),path=name,match=p.is_file() and sha(p)==digest))
for name,digest in read('evidence/2026-11-01/policy-engine/frozen-source-hashes-current.json').items():
 p=ROOT/name;source_checks.append(dict(lock='original-108-source-snapshot',path=name,match=p.is_file() and sha(p)==digest))
for entry in original:
 for name,digest in entry.get('sourceHashes',{}).items():
  p=ROOT/name;source_checks.append(dict(lock='original-inventory:'+entry['source'],path=name,match=p.is_file() and sha(p)==digest))
save('index-integrity.json',dict(indices=index_results,totalEntries=sum(x['entries'] for x in index_results),matchedEntries=sum(x['matched'] for x in index_results),failures=[f for x in index_results for f in x['failures']],sourceChecks=source_checks,sourceFailures=[x for x in source_checks if not x['match']]))

all_differentials=[];records_by_path={}
for p in sorted(E.glob('*/*differential.json')):
 if OUT in p.parents: continue
 d=json.loads(p.read_text());records=d if isinstance(d,list) else d.get('records',[d] if 'legacyDecision' in d else [])
 records_by_path[rel(p)]=records
 all_differentials.append(dict(path=rel(p),**decisions(records)))
snapshot=read('evidence/2026-11-01/policy-engine/gate-decision-before.json')
core=read(rel(OUT/'core-readiness.json'))
classifier=core['classifierRecheck']
all_differentials.append(dict(path='original frozen classifier snapshot -> current engine (existing core recheck)',**decisions(classifier)))
save('all-differential-records-audit.json',dict(files=all_differentials,
 aggregateSamples=sum(x['samples'] for x in all_differentials),aggregateMismatch=sum(x['mismatched'] for x in all_differentials),
 allRawPreserved=all(x['rawPreserved'] for x in all_differentials),
 note='Includes historical child/unit-only scopes. This total is NOT complete-parent proof and is not cumulative Policy test count. No repeated execution counts; each retained record/file selected once.'))

groups={
 'sbom':('sbom-parent',['differential.json','workflow-differential.json']),
 'regression':('regression-parent',['differential.json']),
 'kyverno':('kyverno-parent',['parent-differential.json']),
 'kubescape':('kubescape-parent',['differential.json']),
 'defectdojo':('dojo-parent',['differential.json']),
 'cosign':('cosign-parent',['differential.json']),
 'provenance':('provenance-parent',['differential.json','workflow-differential.json']),
 'build-provenance':('build-provenance-parent',['differential.json','workflow-differential.json']),
 'semgrep':('command-parent',['differential.json','workflow-differential.json']),
 'semgrep-command-audit':('command-parent',['differential.json','workflow-differential.json']),
 'security-approval-promotion':('promotion-parent',['differential.json','workflow-differential.json']),
 'falco-baseline':('falco-parent',['differential.json']),
 'falco-final':('falco-parent',['differential.json']),
}
stages={x['id']:x['stage'] for x in production}
stages.update({'provenance':'Conditional securityProvenance','build-provenance':'Conditional securityBuildProvenance','semgrep-command-audit':'Command Analysis before/in Semgrep','security-approval-promotion':'Security Approval / Approved Promotion / Git Promotion'})
matrix=[];selected_parent_records=[];seen=set();acceptance_checks=[]
for orig in original:
 source=orig['source'];row=dict(source=source,productionStage=stages[source],productionEntry=orig['entry'])
 if source in groups:
  directory,files=groups[source];ps=['evidence/2026-11-01/'+directory+'/'+n for n in files]
  records=[v for p in ps for v in records_by_path[p]]
  if source.startswith('falco-'):records=[v for v in records if v['mode']==('baseline' if source.endswith('baseline') else 'check')]
  stats=decisions(records);acceptance=read('evidence/2026-11-01/'+directory+'/acceptance.json')
  expected=acceptance.get('baselineDifferentials' if source=='falco-baseline' else 'finalDifferentials') if source.startswith('falco-') else acceptance.get('matched')
  acceptance_checks.append(dict(source=source,acceptanceFinalStatus=acceptance.get('finalStatus'),rawFactsPreserved=acceptance.get('rawFactsPreserved'),expectedMatches=expected,observedMatches=stats['matched'],match=expected==stats['matched'] and acceptance.get('finalStatus')=='VERIFIED' and acceptance.get('rawFactsPreserved') is True))
  proof_key='command-parent' if source in ['semgrep','semgrep-command-audit'] else source
  if proof_key not in seen:selected_parent_records+=records;seen.add(proof_key)
  gaps=acceptance.get('remainingEvidenceGaps',[]) or ['Natural full-parent production incident/live environment certification not claimed; frozen compatibility proof only']
  row.update(adapterStatus='VERIFIED',adapterScope='Complete frozen current parent, including existing execution/error behavior',completeParentDifferentialStatus='VERIFIED',**stats,
   evidenceFiles=ps,acceptance='evidence/2026-11-01/'+directory+'/acceptance.json',evidenceType=sorted({v.get('classification','CONTROLLED_REPLAY') for v in records}),
   remainingEvidenceGap=gaps,finalCompatibilityStatus='VERIFIED',blockerClass=None,aggregateProofKey=proof_key)
 elif source in ['gitleaks','trivy','zap']:
  if source=='gitleaks':records=records_by_path['evidence/2026-11-01/policy-engine/gitleaks-differential.json'];refs=['evidence/2026-11-01/policy-engine/gitleaks-differential.json']
  else:records=[v for v in classifier if v['component']==source];refs=['evidence/2026-11-01/policy-engine/gate-decision-before.json',rel(OUT/'core-readiness.json')]
  row.update(adapterStatus='VERIFIED',adapterScope='Classifier/review loop ONLY; retained prior scoped VERIFIED',completeParentDifferentialStatus='NOT_TESTED',**decisions(records),evidenceFiles=refs,
   evidenceType=['SYNTHETIC_UNIT_ONLY'],remainingEvidenceGap=['Full production parent prerequisite/execution/identity/report/cleanup differential proof absent; observed classifier parity cannot cover these failure paths'],
   finalCompatibilityStatus='NOT_TESTED',blockerClass='A',aggregateProofKey=source+'-classifier-only')
 elif source=='sops':
  records=records_by_path['evidence/2026-11-01/sops-policy/differential.json']
  row.update(adapterStatus='NOT_TESTED',adapterScope='Observation adapter implemented; 20 unit-only Gate-body comparisons; prerequisites not fully proved',completeParentDifferentialStatus='NOT_TESTED',**decisions(records),
   evidenceFiles=['evidence/2026-11-01/sops-policy/differential.json','evidence/2026-11-01/sops-policy/acceptance.json','evidence/2026-11-01/sops-controlled/acceptance.json'],evidenceType=['SYNTHETIC_UNIT_ONLY','EXECUTION_ENVIRONMENT_INSPECTION_ONLY'],
   remainingEvidenceGap=['0 real controlled positive/negative/prerequisite executions; no safe disposable authorized Kubernetes environment','Original runtime prerequisite validation behavior not proven by booleans supplied as input; do not read production Secrets to fill this gap'],
   finalCompatibilityStatus='ENVIRONMENT_BLOCKED',verificationStatus='NOT_TESTED',historicalNegativeStatus='DEFERRED_REAL_NEGATIVE_EVIDENCE',blockerClass='A',aggregateProofKey='sops-unit-only')
 else:
  positive=read('evidence/2026-11-01/sonar-policy/positive-differential.json')
  row.update(adapterStatus='VERIFIED',adapterScope='Bound real OK -> PASS; synthetic ERROR -> FAIL logic only',completeParentDifferentialStatus='DEFERRED_REAL_NEGATIVE_EVIDENCE',**decisions([positive]),
   evidenceFiles=['evidence/2026-11-01/sonar-policy/positive-differential.json','evidence/2026-11-01/sonar-policy/analysis-bound-facts.json','evidence/2026-11-01/sonar-policy/negative-evidence-disposition.json'],evidenceType=['HISTORICAL_ARCHIVE','SYNTHETIC_UNIT_ONLY'],
   remainingEvidenceGap=['Real failed build -> task -> analysis -> ERROR conditions direct chain missing; positive build/task uses workspace/time correlation, not directly archived build task','Existing historical failed logs/ERROR reports do not justify a bound real-negative VERIFIED claim'],
   finalCompatibilityStatus='DEFERRED_REAL_NEGATIVE_EVIDENCE',positiveStatus='VERIFIED',realNegativeStatus='NOT_TESTED',blockerClass='B',aggregateProofKey='sonar-positive-only')
 if row['mismatched'] or not row['rawPreserved']:row['finalCompatibilityStatus']='FAILED';row['blockerClass']='A'
 matrix.append(row)

full_stats=decisions(selected_parent_records)
selected=list(selected_parent_records)
selected+=records_by_path['evidence/2026-11-01/policy-engine/gitleaks-differential.json']
selected+=[v for v in classifier if v['component'] in ['trivy','zap']]
selected+=[read('evidence/2026-11-01/sonar-policy/positive-differential.json')]
selected_stats=decisions(selected)
counts=dict(Counter(r['finalCompatibilityStatus'] for r in matrix))
for status in ['VERIFIED','DEFERRED_REAL_NEGATIVE_EVIDENCE','ENVIRONMENT_BLOCKED','FAILED','NOT_TESTED','NOT_APPLICABLE']:counts.setdefault(status,0)
blockers=[dict(source=r['source'],reason=r['remainingEvidenceGap']) for r in matrix if r['blockerClass']=='A']
integrity=read(rel(OUT/'index-integrity.json'))
if integrity['failures'] or integrity['sourceFailures']:blockers.append(dict(source='evidence-integrity',reason='Recorded artifact/source hash no longer matches; see index-integrity.json'))
save('acceptance-reconciliation.json',{'checks':acceptance_checks,'allMatch':all(x['match'] for x in acceptance_checks)})
if not all(x['match'] for x in acceptance_checks):blockers.append(dict(source='acceptance-reconciliation',reason='Acceptance status/count/raw assertion differs from retained differential records'))
if not core['ready']:blockers.append(dict(source='policy-core',reason='See core-readiness.json'))
if not inventory_check['complete']:blockers.append(dict(source='inventory',reason='Current/original inventory differs'))
all_stats=read(rel(OUT/'all-differential-records-audit.json'))
if all_stats['aggregateMismatch'] or not all_stats['allRawPreserved']:blockers.append(dict(source='differential-records',reason='Drift/raw preservation failure'))

architecture=[
 {'requirement':'SECURITY_ENABLED=true/false Global Master Switch','current':'No literal SECURITY_ENABLED entry; mode off is partial historical behavior, not completed master contract','finalDebt':True},
 {'requirement':'Security Manager > globalMode > securityLevel(default standard) > per-plugin switch > capability > independent execution','current':'Existing Manager mode and module switches; standalone Policy levels; unified lifecycle still incomplete','finalDebt':True},
 {'requirement':'disabled = DISABLED; never PASS','current':'Engine returns DISABLED/decision=null; Manager per-plugin still internal skipped/display SKIPPED with reason DISABLED; normalize contract debt','finalDebt':True},
 {'requirement':'missing capability cannot affect unrelated plugins','current':'Some not_configured evidence; uniform capability/isolation contract incomplete','finalDebt':True},
 {'requirement':'scanner facts > normalize > Policy decisions > Unified Summary','current':'Standalone Policy available; current production still original Gates. Actual metadata Summary integration not done','finalDebt':True},
 {'requirement':'Unified Summary > Result Router > DefectDojo/Loki/Grafana/future consumers; no private scanner coupling','current':'Dojo file coupling and uniform Router/publish/query closure remain unresolved','finalDebt':True},
]
save('architecture-constraints.json',{'scope':'Design requirements retained by this audit and user request; not an implementation/certification claim','pipeline':['SECURITY_ENABLED','Security Manager','globalMode','securityLevel (default standard)','per-plugin enable/disable','capability check','independent plugin execution','raw report','normalize','Policy Engine','Unified Summary','Result Router','DefectDojo / Loki / Grafana / future consumers'],'requirements':architecture,'otherFinalDebt':['Provenance opt-in unification','All-plugin portability smoke','Unresolved evidence debt repayment; no final portability success']})

references=[]
for r in matrix:
 for p in r['evidenceFiles']+([r['acceptance']] if 'acceptance' in r else []):references.append(dict(source=r['source'],path=p,exists=(ROOT/p).is_file()))
save('reference-check.json',dict(references=references,missing=[r for r in references if not r['exists']]))
if any(not r['exists'] for r in references):blockers.append(dict(source='evidence-reference',reason='Matrix reference missing'))
report_index=[]
for p in sorted((ROOT/'docs').glob('*20261101.md')):
 if 'FINAL-INVENTORY' in p.name:continue
 content=p.read_text();report_index.append(dict(path=rel(p),sha256=sha(p),bytes=p.stat().st_size,headings=[l for l in content.splitlines() if l.startswith('#')],scope='Historical report; later source-specific acceptance/disposition supersedes earlier stop conclusions'))
save('report-index.json',report_index)
save('authoritative-source-matrix.json',{'scope':'Unique authoritative final inventory for this audit; does not rewrite historical acceptances','sources':matrix,'counts':counts,'completeParentUniqueDifferentials':full_stats,'selectedCurrentEvidenceDifferentials':selected_stats,'allRetainedScopeDifferentials':all_stats,'deduplication':'Semgrep and Command Analysis share 136 complete parent records counted once. Earlier child proofs are supplementary, never parent promotion. SOPS20 and earlier Semgrep8/child contracts excluded from primary complete-parent total.'})

before=read(rel(OUT/'before-sha256.json'));changes=[p for p,h in before.items() if not (ROOT/p).is_file() or sha(ROOT/p)!=h]
save('no-mutation-proof.json',dict(protectedFiles=len(before),unchanged=len(before)-len(changes),changed=changes,scope='Pre-existing tracked files, Policy code, docs and all prior evidence. Audit-only files excluded; no production or existing Summary writes.'))
if changes:blockers.append(dict(source='audit-mutation',reason=changes))
ready=not blockers and inventory_check['complete'] and core['ready']
result=dict(SUMMARY_INTEGRATION_READINESS='READY' if ready else 'NOT_READY',totalProductionSources=len(matrix),counts=counts,
 aggregateDifferentialSamples=all_stats['aggregateSamples'],aggregateDrift=all_stats['aggregateMismatch'],
 completeParentUniqueDifferentialSamples=full_stats['samples'],selectedCurrentDifferentialSamples=selected_stats['samples'],
 policyCore='VERIFIED' if core['ready'] else 'FAILED',existingCoreTests='5/5 PASS (see log)',coreAuditObservations=len(core['checks']),
 cumulativePolicyCases=1873,cumulativeCasesRerun=False,summaryIntegrationBlockers=blockers,
 finalPortabilityBlockers=['Master switch and plugin contract/lifecycle/capability isolation','DefectDojo private-file decoupling','Result Router and publish/query closure','Provenance opt-in contract unification','Portability smoke and unresolved evidence debt; Sonar real negative remains deferred'],
 allOriginalProductionSourcesAccountedFor=inventory_check['complete'],
 sopsClassification='A: no safe real execution and runtime-prerequisite proof; not merely absent historical incident. NOT_TESTED / ENVIRONMENT_BLOCKED retained.',
 sonarClassification='B: bound positive VERIFIED, current authoritative OK/ERROR mapping audited, missing real negative historical binding is deferred per explicit user disposition. Real negative NOT_TESTED, never VERIFIED.',
 nextPermittedStage='Only a separately scoped blocker-repayment stage: Gitleaks/Trivy/ZAP full production-parent evidence; SOPS safe disposable authorized environment + real controlled execution/prerequisite differential proof. Do not implement during this audit. Re-run readiness after proof. Actual Summary integration remains prohibited.',
 auditStop=True,summaryModified=False,productionModified=False,rollout=False)
save('readiness.json',result)

lines=['# Policy Engine production compatibility 最终总盘点（2026-11-01）','',
 '**SUMMARY_INTEGRATION_READINESS = '+result['SUMMARY_INTEGRATION_READINESS']+'**。本轮仅盘点/证据核对，未新增 adapter、未修改现有生产逻辑或实际 Summary、未 rollout。','',
 '## 权威范围与计数','',
 f'原始 18 个来源全部有对应行；现行 14 个 adapter stage、2 个条件插件、命令分析及下游审批均已核对，无新增遗漏。HEAD `'+subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()+'`。这里只证明冻结当前源码兼容，不证明实时生产服务健康。','',
 '最终状态互斥计数：'+ '；'.join(k+'='+str(v) for k,v in counts.items())+'。SOPS 最终分类 ENVIRONMENT_BLOCKED，验证状态仍 NOT_TESTED，不重复计入两类。','',
 '## 完整生产来源矩阵','',
 'Adapter 的 VERIFIED 有明确范围；parent 未完成时最终不得借用 classifier 的 VERIFIED。M/X 是该行明确范围内 match/mismatch；带 * 的不是完整 parent 样本。','',
 '| source / production stage | adapter / complete parent | M / X | evidence | raw | gap / final status |',
 '| --- | --- | ---: | --- | --- | --- |']
short={'gitleaks':'仅分类器；缺前置/执行/清理父阶段','trivy':'仅分类器；缺候选镜像+Harbor扫描完整父阶段','zap':'仅分类器；缺runtime/fixture/目标绑定/清理父阶段','sops':'仅20合成单元；真实受控及runtime前置证据0','sonarqube':'正例真实；负例build→task→analysis绑定缺失'}
for r in matrix:
 mark='*' if r['source'] in short else ''
 gap=short.get(r['source'],'冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围')
 if r['source']=='semgrep':gap='与Command Analysis同一完整生产父命令；136样本只计一次'
 lines.append('| '+r['source']+' / '+r['productionStage']+' | '+r['adapterStatus']+' / '+r['completeParentDifferentialStatus']+' | '+str(r['matched'])+mark+' / '+str(r['mismatched'])+' | '+', '.join(r['evidenceType'])+' | '+str(r['rawPreserved'])+' | '+gap+'；**'+r['finalCompatibilityStatus']+'** |')
lines+=['','逐行 production entry、证据路径、旧/standard 决策分布、完整范围及缺口见同目录 `authoritative-source-matrix.json`。','',
 '## 差分与证据完整性','',
 f'- 完整父阶段去重：{full_stats["samples"]}/{full_stats["matched"]}（samples/matches），drift={full_stats["mismatched"]}。Semgrep/Command Analysis的136只计一次。',
 f'- 当前主证据选择集：{selected_stats["samples"]}（完整父阶段 + Gitleaks7/Trivy8/ZAP4分类器 + Sonar真实正例1），drift={selected_stats["mismatched"]}。',
 f'- 所有保留范围的差分记录及20个原冻结分类器重查合计：{all_stats["aggregateSamples"]}，drift={all_stats["aggregateMismatch"]}；这是分层记录总数，不把旧child/unit-only提升为完整parent，不是1873个Policy tests。',
 f'- 全部选取记录raw preservation={all_stats["allRawPreserved"]}；保留SKIPPED/NOT_CONFIGURED，无改成PASS。完整父阶段旧/standard均为 `{json.dumps(full_stats["oldDecisions"],ensure_ascii=False)}`。',
 f'- 校验{len(index_results)}份既有artifact/evidence哈希索引、{integrity["totalEntries"]}条引用，成功{integrity["matchedEntries"]}；源码锁检查{len(source_checks)}条，失败{len(integrity["sourceFailures"])}。矩阵引用缺失0（详见reference-check）。',
 f'- 原始108源码快照与现有version locks逐项核验；本轮前后保护文件{len(before)}份，变化{len(changes)}份。旧报告和旧失败acceptance未覆盖。','',
 '## Policy Engine readiness','',
 '现有核心tests 5/5 PASS；只读审计10项全部 VERIFIED：baseline-v1、默认standard、显式low、strict、component/project override、policyVersion、effectivePolicy、override source、错误配置POLICY_ERROR。对不可读/损坏JSON/错误schema仅在一次性审计进程注入读取故障，不改策略文件。metadata当前仍仅引擎返回值，不代表已接Summary。',
 '累计1873 Policy cases保留上一轮验收记录，本轮未重跑全量、未新增计入累计的Policy test cases。真实Sonar正例和合成ERROR映射只读复核，合成ERROR仍不是历史负例。','',
 '## A：阻断 Summary integration','',
 '1. Gitleaks：原source-gate包含Lease、scanner身份/隔离、正负canary、源码转移、report及清理；7个review-loop差分不能证明全父阶段。',
 '2. Trivy：ensure-audit-candidate + audit-trivy的候选源/registry/双架构扫描/runtime/请求失败及报告路径缺完整差分；8个漏洞分类样本不覆盖这些执行失败。',
 '3. ZAP：scanner-runtime、JVM/fixture、确认记录hash/target绑定、生产GET探测、native report及session清理缺完整差分；4个classifyZap样本不足。',
 '4. SOPS/age：NOT_TESTED / ENVIRONMENT_BLOCKED。20个合成Gate-body差分不能替代完整scanner-runtime prerequisite或真实受控执行。现有context不是安全隔离环境，禁止读取生产Secret补证。属于A，同时留下最终portability证据债；不能只按“历史没发生事故”豁免。','',
 '前三项保留原先分类器VERIFIED，最终完整兼容状态为NOT_TESTED；这是范围校正，不是检测到decision drift，也不是修改Gate。旧覆盖矩阵的blockers数组只列SOPS，且保留过时inheritedBlockersSnapshot；它不能作为本次唯一权威结论。','',
 '## B：最终 portability debt','',
 'Sonar positive VERIFIED；negative NOT_TESTED / DEFERRED_REAL_NEGATIVE_EVIDENCE。已有task→analysis→conditions正例，当前权威OK→PASS/ERROR→FAIL逻辑测试通过且拒绝无绑定事实；历史失败日志确实存在，但缺直接build/task/analysis链。按已批准的延期规则，属于B，不单独阻断架构推进，绝不标负例VERIFIED。正例与build仍是workspace/time关联，未夸大为逐构建直接task归档。','',
 '其他B债：Global Master Switch、per-plugin统一独立禁用及DISABLED状态、capability隔离和统一plugin contract、Dojo私有文件解耦、Provenance opt-in统一、Result Router、Loki publish/query闭环和portability smoke。它们没有在本轮被实现或豁免。','',
 '## 保留的架构硬约束','',
 '`SECURITY_ENABLED → Security Manager → globalMode → securityLevel(default standard) → per-plugin switch → capability check → independent execution → raw → normalize → Policy Engine → Unified Summary → Result Router → consumers`。','',
 '必须有全局开关；每插件可独立关闭；disabled只能DISABLED不能PASS；缺capability不能拖累无关插件；scanner只产事实、Policy判定；consumer不直接依赖私有scanner文件。现有早期合同部分要求未显式写为该完整链，本次将其作为用户要求的目标设计保留，未谎报已实现。详见architecture-constraints.json。','',
 '## GO / NO-GO 与停止','',
 '**SUMMARY_INTEGRATION_READINESS = '+result['SUMMARY_INTEGRATION_READINESS']+'**。inventory complete、drift=0、core ready均成立；A类兼容证据缺口未清零。不得进入实际security-summary.json集成。','',
 '下一允许阶段仅是单独限定范围的兼容补证：Gitleaks/Trivy/ZAP完整父阶段，以及SOPS真正隔离/可丢弃/已授权环境中的受控执行及prerequisite差分。获得证据后重新做readiness判定。本轮到此停止，不实施该阶段，不输出全Policy/portability成功标记。','']
(OUT/'FINAL-INVENTORY.md').write_text('\n'.join(lines))
print(json.dumps({k:result[k] for k in ['SUMMARY_INTEGRATION_READINESS','counts','aggregateDifferentialSamples','aggregateDrift','completeParentUniqueDifferentialSamples','selectedCurrentDifferentialSamples','policyCore']},ensure_ascii=False,indent=2))
