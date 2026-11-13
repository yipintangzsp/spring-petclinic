from pathlib import Path
import json,hashlib,re,datetime,sys,shutil
O=Path(__file__).resolve().parent;P=O.parent/'runtime-proxy-history-recovery';R=O.parents[2]
sys.path.insert(0,str(O));from history_tools import OLD,NEW,ordered,timestamp
read=lambda n:json.loads((O/n).read_text());prior=lambda n:json.loads((P/n).read_text())
sha=lambda b:hashlib.sha256(b).hexdigest()
save=lambda n,x:(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
frozen=json.load(open(R/'evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json'))['checks']
for c in frozen:assert sha((R/c['path']).read_bytes())==c['expected'],c['path']
for p,h in read('implementation-before.json').items():assert sha((R/p).read_bytes())==h,p
seals=[]
names=[Path(s['path']).name for s in prior('source-hash-preservation.json')['oldEvidenceSeals']]+[P.name]
for name in names:
 b=O.parent/name;m=json.load(open(b/'evidence-sha256.json'))
 for p,h in m['files'].items():assert sha((b/p).read_bytes())==h,(name,p)
 seals.append({'path':str(b.relative_to(R)),'manifestSha256':sha((b/'evidence-sha256.json').read_bytes()),'files':len(m['files'])})
save('source-hash-preservation.json',{'frozenReferences':len(frozen),'uniqueFiles':len(set(x['path'] for x in frozen)),'implementationFiles':len(read('implementation-before.json')),'allUnchanged':True,'oldSeals':seals,'oldSealedFileCount':sum(s['files'] for s in seals),'compatibilityCount':2202,'compatibilityCountChanged':False,'checkpointContractChanges':0})
counts={}
for name,expected in [('runtime-tests',143),('candidate-tests',40),('completeness-negative',11),('policy-core-tests',5),('regression-tests',147),('checkpoint-integrity-tests',12)]:
 t=(O/(name+'.log')).read_text();c={k:int(v) for k,v in re.findall(r'(?m)^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',t)};assert c.get('tests')==c.get('pass')==expected and c.get('fail')==c.get('skipped')==c.get('cancelled')==0,(name,c);counts[name]=c
for name,n in [('archive-probe-tests',8),('history-tools-tests',16)]:
 assert re.search(r'Ran '+str(n)+r' tests.*\n\nOK\s*$',(O/(name+'.log')).read_text(),re.S);counts[name]={'tests':n,'pass':n,'fail':0}
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
counts['policy-contract']={'checks':10,'pass':10,'fail':0}
# Re-evaluate real historical bounds from original capture facts, not from mtime alone.
rows=prior('capture-command-timing.json')['records'];a=next(x for x in rows if x['beforeArgument']);b=next(x for x in rows if x['afterArgument']);old=json.load(open(O.parent/'runtime-14-checkpoint-guard-review/local-config-before.json'))['files']['proxyConfig'];new=json.load(open(O.parent/'runtime-14-checkpoint-guard-review/local-config-after.json'))['files']['proxyConfig']
tc=[ordered(prior('drift-timeline.json')['events']),a['startTimeMs']<=a['completedTimeMs'],a['completedTimeMs']<b['startTimeMs']<=b['completedTimeMs'],a['exitCode']==b['exitCode']==0,old['sha256']==OLD and new['sha256']==NEW and OLD!=NEW,old['mtimeNs']/1e6<a['startTimeMs'],a['startTimeMs']<new['mtimeNs']/1e6<b['completedTimeMs'],prior('observation-T0.json')['files'][0]['rawSha256']==NEW];assert all(tc)
save('timeline-recheck.json',{'source':'../runtime-proxy-history-recovery/drift-timeline.json','sourceSha256':sha((P/'drift-timeline.json').read_bytes()),'checks':len(tc),'pass':sum(tc),'exactWriteTimeKnown':False,'newWriterProof':False})
counts['historical-timeline-consistency']={'checks':8,'pass':8,'fail':0}
save('test-counts.json',{'suites':counts,'totalTestsAndChecks':sum(c.get('tests',c.get('checks',0)) for c in counts.values()),'allPassed':True,'realRuntimeCompletenessProven':False})
archives=read('large-archive-results.json');assert len(archives['archives'])==23 and archives['oldMatchingCount']==0
def dbmeta(base):
 t=(base/'trivy-filesystem-after.stdout').read_text();f={l.split('|')[0]:l for l in t.splitlines() if l.startswith('/home/scanner/.cache/trivy/') and len(l.split('|'))==7};h={p:x for x,p in re.findall(r'(?m)^([a-f0-9]{64})  (/home/scanner/.cache/trivy/(?:db|java-db)/metadata.json)$',t)};assert f and len(h)==2;return {'files':f,'metadataHashes':h}
assert dbmeta(O)==dbmeta(P)
for k in ['pod','pvcs','volumes','statefulsetSpecSha256','environmentConfigurationSha256']:assert read('trivy-storage-after.json')[k]==prior('trivy-storage-after.json')[k]
assert read('dojo-governance-after.json')==prior('dojo-governance-after.json')
j=next(x for x in read('live-jenkins-final.json')['jobs'] if x['job']=='petclinic-ci');assert j['latestBuild']==270 and j['result']=='SUCCESS' and not j['building'] and j['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
live=read('live-protected-final.json');nodes=read('node-lease-postflight.json')['nodes'];assert len(nodes)==3 and all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in nodes);assert live['http']['status']==200 and live['argocdSync']=='Synced' and live['argocdHealth']=='Healthy'
current=read('current-proxy-readonly.json');assert not current['lanExposure'];assert any('127.0.0.1:10808 (LISTEN)' in x['output'] for x in current['listeners'])
save('protected-state.json',{'jenkinsBuild':270,'result':'SUCCESS','v1SummarySha256':j['summarySha256'],'currentProxySha256':current['sha256'],'currentProxyBytes':current['bytes'],'matchesPreviousLatestObservedProxyBytes':current['sha256']==prior('current-post-additional-drift.json')['sha256'],'historicalProxySemantics':'UNKNOWN','proxyAgentWrites':0,'proxyAgentRestarts':0,'newBaseline':False,'TrivyConfigAndDbMetadataUnchanged':True,'fullDbContentShaRecomputed':False,'TrivyRefreshes':0,'TrivyGuardChanges':0,'DojoSelectedMetadataUnchanged':True,'DojoWrites':0,'nodesReady':[n['name'] for n in nodes],'petclinicReady':3,'readyEndpoints':3,'HTTP':200,'argocd':'Synced/Healthy','deploymentSpecUnchanged':live['deploymentSpecUnchanged'],'release':0,'rollout':0,'newBuilds':0})
verdict=prior('verdict.json');save('verdict.json',verdict)
save('stop-receipt.json',{'historicalEvidence':'INSUFFICIENT','checkpoint':'FAILED','resumeAllowed':False,'nextStrategy':'ESTABLISH_NEW_CLEAN_BASELINE','explicitApprovalRequiredForReset':True,'baselineResetPerformed':False,'checkpointContractChanges':0,'proxyWrites':0,'proxyRestarts':0,'TrivyRefreshes':0,'DojoWrites':0,'release':0,'rollout':0,'searchStoppedAtDeclaredBounds':True,'compressedArchivesNotFullyTraversed':14})
items=prior('report-items.json')
def setitem(i,text):items[i-1]['result']=text
setitem(1,'继承已封存150小配置候选、38会话、174归档及303构建/4082归档条目的检索结果。本轮仅补查23个此前因大小上限未打开的归档：9个未压缩TAR遍历至末尾，14个gzip到32MiB解压读取上限停止；新找到9个配置条目，旧hash匹配0。逐条路径/entry时间/hash/大小/信任等级见large-archive-results.json。14个gzip未全部遍历，不能声称全盘穷尽或不存在旧内容。')
setitem(5,'仍未找到可信旧generated config内容；本轮新增9个归档配置条目均UNTRUSTED，不提升为pre-drift权威。历史具体主config路径及部分运行记录沿用前轮封存证据。')
setitem(8,'本轮没有新增文件写入审计、GUI保存/订阅刷新事件。前轮596历史日志及会话记录仍仅支持候选GUI=WEAK；没有因补查归档或后续运行态稳定提升writer归因。')
setitem(13,'更早可信记录127.0.0.1:10808；本轮当前真实lsof仍见回环10808/10812，详见current-proxy-readonly.json。旧10812基线未知。不得拿之前查询失效PID6529的T0作为当时监听证明。')
setitem(16,'旧完整routing UNKNOWN；本轮生成配置domainStrategy='+str(current['routingMode'])+'，摘要见current-proxy-readonly.json。不是旧→新等价证明。')
setitem(27,'历史A/B/C仍未满足：UNEXPLAINED、语义UNKNOWN、writer证据WEAK。本轮当前主配置SHA与前轮最新6516字节观察一致，但单点相同不证明稳定性或原漂移安全；不得重新验收checkpoint。')
setitem(29,'YES（若历史无法恢复而要继续checkpoint）。本轮附件与前轮字节完全相同，仍明确禁止自动reset；未建立epoch/version。')
setitem(30,'STOP。已按声明边界结束历史恢复，不反复重扫。下一策略ESTABLISH_NEW_CLEAN_BASELINE须明确批准后另轮执行：记录当前完整语义/变化来源、有限稳定观察、新epoch/version、永久保留旧FAILED/UNEXPLAINED，禁止追认旧漂移安全。本轮不执行reset。')
setitem(31,'本轮重跑runtime143/143 PASS，隔离completeness-negative11/11 PASS。')
setitem(32,'本轮candidate40/40 PASS，一次性checkout已移除。')
setitem(33,'本轮Policy core5/5 PASS。')
setitem(34,'本轮contract10/10 PASS；未修改任何现有Gate或checkpoint hash合同。')
setitem(35,'本轮Regression147/147 PASS；新归档读取边界测试8/8、检索/parser/时间线unit16/16、真实历史时间界限重核8/8均PASS；共400项本地测试/检查，不是新增Policy兼容样本计数。')
setitem(36,'本轮原FAILED checkpoint离线完整性12/12 PASS；12组1005个旧封存文件全部hash一致，含上一轮95文件。新证据独立封存，不覆盖旧结果。')
setitem(37,'455冻结引用/229唯一文件、77实现文件全一致，兼容计数2202保持；无源码/生产Gate/发布/合同修改。')
setitem(38,'新只读复核petclinic-ci仍#270 SUCCESS，没有新build；历史Jenkins归档检索沿用上轮封存记录，不宣称本轮新增归档。')
setitem(39,'V1仍active，Summary SHA='+j['summarySha256']+'。Trivy存储/DB文件元数据及metadata.json hash、Dojo所选元数据与前轮一致；未重新计算完整DB内容SHA；未激活Summary V2。')
setitem(40,'本轮只读复核三个节点Ready；非连续HA演练结论。')
setitem(41,'本轮复核PetClinic3/3、3个Ready Endpoint、HTTP200，Argo Synced/Healthy及Deployment spec未变，Harbor7个Pod Ready。')
save('report-items.json',items)
text='# 历史代理证据恢复：大归档补查与停止报告\n\n本轮附件与上一轮字节相同，SHA256=5d6a8c85a11a7eb392635a3d36fe244fc5d28a084516e25a480181295c36a66d。没有获得基线reset授权。\n\n'
text+='原漂移：6648字节/e3c322… → 6306字节/b702ff…仍UNEXPLAINED。前轮另有6516字节/1d7962…及主core替换，本轮当前采样仍为'+current['sha256']+'，'+str(current['bytes'])+'字节；不追认原漂移安全，不建立新baseline。\n\n'
text+='\n\n'.join(str(x['item'])+'. **'+x['name']+'** — '+x['result'] for x in items)
text+='\n\n## 最终裁决\n\n```yaml\n'+'\n'.join(k+': '+str(v) for k,v in verdict.items())+'\n```\n\n'
text+='本轮是增量补查。前轮未重跑的历史日志/会话/旧运行事实均明确引用封存记录：[前轮完整报告](../runtime-proxy-history-recovery/REPORT-43.md)。新增[归档结果](large-archive-results.json)、[当前保护核验](protected-state.json)、[测试计数](test-counts.json)、[停止收据](stop-receipt.json)。\n'
(O/'REPORT-43.md').write_text(text)
shutil.copyfile(P/'private-value-check.py',O/'private-value-check.py')
print(json.dumps({'allLocalTestsAndChecks':400,'oldSealedFiles':sum(s['files'] for s in seals),'checkpoint':'FAILED','baselineReset':False,'reportItems':len(items)}))
