"""Offline derivations. Sources are never modified; all outputs exclusive-create."""
from pathlib import Path
import json,datetime,re,statistics,hashlib
O=Path(__file__).resolve().parent;R=O.parents[2];L=R/'evidence/2026-11-05/security-manager-v2-loki'
read=lambda n:json.loads((O/n).read_text());old=lambda n:json.loads((L/n).read_text());iso=lambda t:datetime.datetime.fromtimestamp(float(t),datetime.timezone.utc).isoformat();bjt=lambda s:datetime.datetime.fromisoformat(s.replace('Z','+00:00')).astimezone(datetime.timezone(datetime.timedelta(hours=8))).isoformat()
def put(n,x):
 with(O/n).open('x')as f:json.dump(x,f,indent=2,ensure_ascii=False);f.write('\n')
i=read('inventory.json');prom=read('prometheus.json');follow=read('prometheus-followup.json');logs=read('runtime-logs.json');journal=read('journal.json');local=read('local-execution.json');host=read('local-host.json');current=read('production-final.json')
def series(name,source=prom):return next(q for q in source['queries']if q['name']==name).get('data',{}).get('data',{}).get('result',[])
def changes(values):
 out=[];old=None
 for t,v in values:
  if v!=old:out.append({'evaluationTime':iso(t),'value':v});old=v
 return out
stats={}
for name in ['node-load','node-availability','node-cpu','cpu-pressure','memory-pressure','io-pressure','disk-available','pod-cpu','pod-memory','pod-ready','restart','deployment-ready','node-ready-pressure']:
 rows=[]
 for s in series(name):
  m=s['metric'];vs=s.get('values',[])
  if not vs:continue
  numeric=[(t,float(v))for t,v in vs];mn=min(numeric,key=lambda v:v[1]);mx=max(numeric,key=lambda v:v[1])
  rows.append({'labels':m,'points':len(vs),'firstEvaluationTime':iso(vs[0][0]),'lastEvaluationTime':iso(vs[-1][0]),'min':mn[1],'minEvaluationTime':iso(mn[0]),'max':mx[1],'maxEvaluationTime':iso(mx[0]),'evaluationGaps':[[iso(a[0]),iso(b[0])]for a,b in zip(vs,vs[1:])if b[0]-a[0]>30],**({'changes':changes(vs)}if name in ['pod-ready','restart','deployment-ready','node-ready-pressure']else{})})
 stats[name]=rows
readyPodIds={s['metric']['uid']for s in series('pod-ready')};pets=[p for p in i['pods']if p['labels'].get('app')=='petclinic'];assert len(pets)==3 and readyPodIds=={p['uid']for p in pets}
before=old('production-before.json');bp=before['host']['production'];initialByUid={p['uid']:p for p in bp['pods']};podRows=[]
for p in pets:
 c=p['containerStatuses'][0];initial=initialByUid[p['uid']]['containers'][0];term=c['lastState']['terminated'];assert term['exitCode']==143 and term['reason']!='OOMKilled';assert c['restartCount']-initial['restartCount']==1
 podRows.append({'pod':p['name'],'uid':p['uid'],'node':p['node'],'createdAt':p['createdAt'],'deletionTimestamp':p['deletionTimestamp'],'sameUidAsBefore':True,'restartBefore':initial['restartCount'],'restartAfter':c['restartCount'],'restartDelta':1,'lastTerminated':term,'currentRunningSince':c['state']['running']['startedAt'],'readyRecoveredAt':next(c['lastTransitionTime']for c in p['conditions']if c['type']=='Ready'),'phaseAtCapture':p['phase'],'conditionAtCapture':'Ready','notAnOOMConclusionScope':'lastState reason/exit, kernel bounded window and matching liveness events; not absence inferred from current health'})
owned=[s for s in i['replicaSets']if any(r.get('uid')==i['deployment']['uid']for r in s.get('ownerReferences',[]))];assert all(s['createdAt']<'2026-11-05T02:05:00Z'for s in owned)
checks={'sameDeploymentUid':bp['deploymentUid']==i['deployment']['uid'],'sameGeneration':bp['generation']==i['deployment']['generation']==175,'sameSpecHash':bp['specSha256']==i['deployment']['specSha256']==current['host']['production']['specSha256'],'sameImage':bp['image']==i['deployment']['image']==current['host']['production']['image'],'samePodUids':set(initialByUid)=={p['uid']for p in pets},'noNewOwnedReplicaSetInWindow':all(s['createdAt']<'2026-11-05T02:05:00Z'for s in owned),'jenkins270AndSummaryUnchanged':before['jenkins']==current['jenkins'],'dockerUnchanged':bp['dockerDaemon']==current['host']['production']['dockerDaemon'],'socketUnchanged':bp['socket']==current['host']['production']['socket']};assert all(checks.values())
endpointRows={}
for s in series('endpoint-slice-counts',follow):
 for t,n in s['values']:
  if float(n)>0:endpointRows.setdefault(t,{}).setdefault(s['metric']['ready'],set()).add(s['metric']['address'])
endpointChanges=[];prior=None
for t,states in sorted(endpointRows.items()):
 v={k:len(s)for k,s in states.items()}
 if v!=prior:endpointChanges.append({'evaluationTime':iso(t),'conditionCounts':v});prior=v
assert any(e['conditionCounts']=={'false':3}for e in endpointChanges)
argo=[];petLogs=[]
for bi,block in enumerate(logs['podLogs']):
 for li,line in enumerate(block.get('windowLines',[])):
  try:t,raw=line.split(' ',1);v=json.loads(raw)
  except(ValueError,TypeError):continue
  if block['container']=='argocd-application-controller'and v.get('application')=='petclinic'and re.search('Updated sync status|Updated health status|Skipping auto-sync: application status',v.get('msg','')):
   argo.append({'sourceTimestamp':t,'nativeTime':v.get('time'),'message':v.get('msg'),'jsonPointer':f'runtime-logs.json#/podLogs/{bi}/windowLines/{li}'})
  if block['container']=='petclinic'and re.search('shutdown|Started PetClinicApplication|HikariPool.*Start|Starting PetClinicApplication|graceful|connection|timeout',v.get('message',''),re.I):petLogs.append({'pod':block['pod'],'previous':block['previous'],'sourceTimestamp':t,'nativeTime':v.get('@timestamp'),'message':v.get('message')[:700],'jsonPointer':f'runtime-logs.json#/podLogs/{bi}/windowLines/{li}'})
jrelevant=[]
for qi,q in enumerate(journal['queries']):
 for li,v in enumerate(q.get('rows',[])):
  if re.search('PLEG is not healthy|Node became not ready|sync configmap cache|sync secret cache|ListPodSandbox|ListContainers|ExecSync cmd',v['message'],re.I):jrelevant.append({'sourceTimestamp':v['timestamp'],'monotonicMicroseconds':v['monotonicMicroseconds'],'message':v['message'],'jsonPointer':f'journal.json#/queries/{qi}/rows/{li}'})
put('analysis.json',{'classification':'OFFLINE_DERIVATION_WITH_SOURCE_POINTERS_NOT_NEW_RUNTIME','statistics':stats,'pods':podRows,'endpointObservedTransitions':endpointChanges,'endpointInterpretation':'addresses persisted; ready=false removes usable backends, not deletion of EndpointSlice. Evaluation timestamps are not precise controller update times.','argo':argo,'petclinicLogExcerpts':petLogs,'nodeLogExcerpts':jrelevant,'productionComparison':checks,'rolloutProof':{'deploymentRevision':i['deployment']['revision'],'activeReplicaSet':'petclinic-7b9fc47976','ownedReplicaSets':[{'name':s['name'],'revision':s['revision'],'createdAt':s['createdAt']}for s in owned],'actualPetclinicRolloutCount':0,'containerRestarts':3,'containerRestartsAreNotRollouts':True},'uncertainty':['Prometheus range evaluation timestamps can reflect earlier scrapes; lookback and missing scrapes prevent exact transition reconstruction.','The 02:14:30–02:21:30 KSM observation gap is unknown, not continuous health or zero utilization.','Guest CPU rates and observed maxima do not establish missing-period peak or a specific triggering process.','Mac idle-exit memorystatus records are not evidence of QEMU OOM or a causal Loki test memory spike.']})
events=[]
def event(t,what,component,source,impact,confirmation='CONFIRMED',raw=None,kind='SOURCE_EVENT'):
 events.append({'timeUtc':t,'timeBeijing':bjt(t),'rawTime':raw or t,'timestampKind':kind,'event':what,'component':component,'evidence':source,'impact':impact,'confirmation':confirmation})
event('2026-11-05T02:00:30.404904+00:00','生产基线3/3、HTTP200、Argo Synced/Healthy','baseline','../security-manager-v2-loki/production-before.json','故障前正常','CONFIRMED',kind='SNAPSHOT_COMPLETED_AT')
event('2026-11-05T02:13:15.085838+00:00','本窗口首次取得本地API /metrics timeout/abort日志','devops/k3s','journal.json','本地控制节点已有响应延迟；不是精确业务故障起点')
event('2026-11-05T02:13:16.164476+00:00','containerd ExecSync 超时','devops/containerd','containerd.json','运行时调用异常先于本轮Node测试',raw='2026-11-05T10:13:16.164476203+08:00')
for e in sorted(i['events'],key=lambda e:e.get('firstTimestamp')or''):
 if e['object']['name'].startswith('petclinic-')and e['reason']in['Unhealthy','Killing','Failed']and'2026-11-05T02:05:00Z'<=(e.get('firstTimestamp')or'')<='2026-11-05T02:45:00Z'and('Liveness probe failed'in e['message']or e['reason']=='Killing'and'failed liveness'in e['message']or'sync configmap cache'in e['message']or'sync secret cache'in e['message']):event(e['firstTimestamp'],e['message'],e['object']['name'],'inventory.json#/events','重启或启动受阻；Event createdAt='+e['createdAt']+' 是延迟持久化时间，不是发生时刻')
for a in local['attempts']:event(a['approximateNodeStartFromDurationAndTapMtime'],'Node测试 attempt'+str(a['attempt'])+' 约开始','Darwin/macOS','local-execution.json','Mock测试；开始时间由duration/mtime估算','PROBABLE',kind='APPROXIMATE_FROM_DURATION_NOT_AUTHORITATIVE_START');event(a['tapWrittenAt'],'Node测试 attempt'+str(a['attempt'])+' TAP写入完成','Darwin/macOS','local-execution.json','进程已退出，文件写入时刻不是精确退出时刻',kind='FILE_WRITE_AFTER_PROCESS_EXIT')
event('2026-11-05T02:18:29Z','三个旧JVM lastState均退出143','PetClinic on devops','inventory.json#/pods','kubelet liveness重启，未见OOMKilled，不是Pod删除')
for v in jrelevant:
 if'Node became not ready'in v['message']:event(v['sourceTimestamp'],'Node Ready=false，PLEG超过3分钟阈值','devops/kubelet',v['jsonPointer'],'同一节点3副本共享故障域')
for v in argo:
 if v['message'].startswith('Updated'):event(v['sourceTimestamp'],v['message'],'Argo petclinic',v['jsonPointer'],'状态/健康观测变化；无实际rollout',raw=v['nativeTime'])
for e in endpointChanges:
 if e['evaluationTime']>'2026-11-05T02:05:00+00:00':event(e['evaluationTime'],'EndpointSlice已观测条件 '+str(e['conditionCounts']),'Service discovery','prometheus-followup.json#/queries/0','地址保留，Ready后端变化；非精确转换时刻',kind='PROMETHEUS_EVALUATION_TIME')
for p in podRows:event(p['currentRunningSince'],'同UID新容器启动',p['pod'],'inventory.json#/pods','kubelet自动重建容器');event(p['readyRecoveredAt'],'Pod Ready恢复',p['pod'],'inventory.json#/pods','容器启动与探针恢复，不是新版本发布')
http502=read('http502-tool-observation.json');event(http502['observations'][0]['timestamp'],'已观察到HTTP502；实际请求在02:21:31.756Z至本时刻之间','business HTTP','http502-tool-observation.json','精确请求时刻缺失',kind='TOOL_ERROR_OBSERVATION_UPPER_BOUND')
legacy=old('health-followup.json');event('2026-11-05T02:27:35.066186+00:00','503和Deployment 0/3已观察；实际GET在02:27:18.975195Z之后、本时刻之前','business HTTP / API','../security-manager-v2-loki/health-followup.json','不能把文件写入时间当503精确起点',kind='ARTIFACT_WRITE_UPPER_BOUND')
event('2026-11-05T02:30:04.125459+00:00','3/3、HTTP200、Argo Synced/Healthy已复核','baseline','../security-manager-v2-loki/production-final.json','业务恢复已观察；非精确首次200时间',kind='SNAPSHOT_COMPLETED_AT')
put('timeline.json',{'queryWindowUtc':['2026-11-05T02:05:00Z','2026-11-05T02:45:00Z'],'timezone':'Asia/Shanghai = UTC+08:00','events':sorted(events,key=lambda e:e['timeUtc']),'preciseHttpOutageStartEnd':'UNKNOWN','first502ObservationIntervalUtc':['2026-11-05T02:21:31.756Z',http502['observations'][0]['timestamp']],'first503ObservationIntervalUtc':['2026-11-05T02:27:18.975195Z','2026-11-05T02:27:35.066186Z'],'causalityWarning':'Time overlap is not causality; sources preserve native timestamp, persistence, collection and evaluation distinctions.'})
verdict={'PRODUCTION_TRANSIENT_INCIDENT':'CONFIRMED','INCIDENT_TIME_WINDOW':'2026-11-05T02:13:15.085838+00:00–2026-11-05T02:30:04.125459+00:00 (evidence envelope; precise HTTP outage boundaries UNKNOWN)','PETCLINIC_0_OF_3_CAUSE':'CONFIRMED','HTTP_502_503_CAUSE':'PROBABLE','ARGOCD_ABNORMALITY_CAUSE':'CONFIRMED','NODE_RESOURCE_CORRELATION':'CONFIRMED','LOKI_CANDIDATE_TEST_CAUSALITY':'UNKNOWN','ROOT_CAUSE':'UNDETERMINED','RECOVERY_MECHANISM':'CONFIRMED','CURRENT_PRODUCTION_HEALTH':'HEALTHY','PRODUCTION_FIX_REQUIRED':'UNDETERMINED','PRODUCTION_FIX_EXECUTED':'NO','EVIDENCE_WRITE_BOUNDARY':'VERIFIED','SECURITY_MANAGER_CANDIDATE':'VERIFIED','PRODUCTION_SECURITY_MANAGER':'NOT_ACTIVE','FINAL_WIRED_CAPABILITY':'14/16','ORIGINAL_EVIDENCE_INTEGRITY':'FAILED','RELEASE_COUNT':0,'ROLLOUT_COUNT':0}
put('verdict.json',{'verdict':verdict,'decisionCategory':'C: root trigger undetermined, currently recovered; no speculative production modification','rootCauseConfidence':'UNKNOWN','confirmedFailureMechanism':'same devops node runtime/PLEG stall + probe failures -> intentional JVM restarts and delayed recreation/cache sync; unusable Service backends; repo-server restart -> Argo comparison error','contributingFactors':[{'status':'CONFIRMED','factor':'All three PetClinic replicas on devops'},{'status':'CONFIRMED','factor':'High guest CPU contention and missing observability during incident'},{'status':'PROBABLE','factor':'CPU/scheduler contention contributed to runtime/API/probe delay; initiating task/process not identified'}],'testCausality':{'directScannerOrPipelineProductionMutation':'NOT_SUPPORTED','onsetAfterTestExecution':'NOT_SUPPORTED; runtime/probe errors precede first Node-test dispatch','sharedPhysicalHost':'CONFIRMED by QEMU UUID','indirectHostResourceContribution':'UNKNOWN; historical per-test/host CPU memory IO not captured; idle-exit messages alone do not establish pressure causality'},'recurrenceRisk':{'status':'POSSIBLE','explanation':'Same single-node failure domain remains; initiating source unknown. Current healthy snapshot is not a stability guarantee.'},'scope':'Read-only incident analysis; candidate verification inherited, no security tests rerun; actual PetClinic rollout count verified from generation/RS/UID/spec and Argo log evidence.'})
print(json.dumps({'derivedFiles':['analysis.json','timeline.json','verdict.json'],'timelineEvents':len(events),'checks':checks,'actualPetclinicRolloutCount':0,'rootCause':'UNDETERMINED'}))
