const $=id=>document.getElementById(id);
let data;
const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
const time=v=>v?new Date(v).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})+' +08:00':'未提供';
const tone=s=>s==='PASS'?'pass':s==='FAIL'||s==='ERROR'||s==='POLICY_ERROR'?'fail':s==='WARN'?'warn':'neutral';
const row=(label,value)=>{const r=el('div',undefined,'card-row');r.append(el('span',label),el('b',value??'—'));return r;};
function source(parent,src){if(!src){parent.append(el('span','UNAVAILABLE'));return;}parent.append(el('code',src.path,'source-path'),el('span','文件 SHA-256','detail-label'),el('code',src.sha256));}
function renderRun(){
  const r=data.runs.find(r=>r.runId===$('scenario').value);if(!r)return;
  $('run-id').textContent=r.runId;$('run-time').textContent=time(r.completedAt);
  $('policy').textContent=r.availability==='AVAILABLE'?`${r.policyVersion} / ${r.securityLevel} / ${r.globalMode}`:'UNAVAILABLE';
  $('overall').replaceChildren(el('span',r.overallDecision??'UNAVAILABLE','tag '+tone(r.overallDecision)));
  $('run-description').textContent=r.availability==='AVAILABLE'?`项目 ${r.projectId} · ${r.profile} · 同一 Run 的原始判定，不重新求值。`:r.reason;
  $('plugin-grid').replaceChildren();
  for(const p of r.plugins){
    const card=el('article',undefined,'plugin '+(tone(p.policyDecision)==='fail'||['ERROR','POLICY_ERROR'].includes(p.executionStatus)?'bad':p.executionStatus==='DISABLED'?'off':''));card.dataset.plugin=p.pluginId;
    const top=el('div',undefined,'card-top');top.append(el('h3',p.pluginId),el('span',p.evidenceClass??'UNAVAILABLE','tag '+(p.evidenceClass==='REAL'?'real':'neutral')));
    card.append(top,el('p',{gitleaks:'凭据泄漏检测 / 受控目录',semgrep:'代码规则检测 / 受控源码',cosign:'离线 Blob 验签 / 非生产信任验证',trivy:'镜像漏洞扫描 / 非生产 Harbor 候选',kyverno:'集群准入评估 / 现行 Kyverno 策略'}[p.pluginId],'plugin-sub'));
    const decision=p.policyDecision??(p.executionStatus==='DISABLED'?'DISABLED':p.executionStatus??'UNAVAILABLE');
    card.append(el('div',decision,'decision '+(p.policyDecision==='PASS'?'pass-text':p.policyDecision==='FAIL'?'fail-text':'off-text')),el('p',p.policyDecision?'原始 Policy Decision':'未产生 Policy Decision','decision-label'));
    const execution=el('div',undefined,'execution');execution.append(el('span',p.executionStatus??'UNAVAILABLE','tag neutral'),el('span','REPLAY','tag replay'));card.append(execution);
    card.append(row('插件配置',p.enabled===true?'ENABLED':p.enabled===false?'DISABLED':'UNAVAILABLE'),row('旧 Gate',p.oldGateDecision),row('Policy 求值次数',p.evaluationCount),row('执行完成',time(p.completedAt)));
    const d=el('div',undefined,'digest');d.append(el('span','RESULT DIGEST','detail-label'),el('code',p.resultDigest??'UNAVAILABLE'));card.append(d);
    const details=el('details');details.append(el('summary','证据与执行范围'));
    for(const [key,value] of [['范围',p.executionScope],['Raw report SHA-256',p.rawReportDigest],['Fact digest',p.factDigest],['校验',p.integrity],['原因',p.failureReason??p.reason]])if(value)details.append(el('p',`${key}: ${value}`));
    if(p.policy){details.append(el('p',`Policy ${p.policy.policyVersion??'UNAVAILABLE'} / ${p.policy.securityLevel??'UNAVAILABLE'} / ${p.policy.profile??'UNAVAILABLE'}`));const policy=el('details');policy.append(el('summary','已有 effectivePolicy / appliedOverrides'),el('pre',JSON.stringify({effectivePolicy:p.policy.effectivePolicy,appliedOverrides:p.policy.appliedOverrides,factDigest:p.policy.factDigest},null,2)));details.append(policy);}
    source(details,p.source);card.append(details);$('plugin-grid').append(card);
  }
  $('source').replaceChildren();source($('source'),r.source);
  if(r.configuration){$('source').append(el('p','Effective Config · 已验证 seal 绑定'));source($('source'),r.configuration.source);}
  if(r.artifact){$('source').append(el('p','Candidate Summary / Artifact Seal · '+r.artifact.fileCount+' 个归档文件'));source($('source'),r.artifact.seal);}
  renderCandidate();
}
function renderCandidate(){
 if(!data)return;
 const selected=data.runs.find(r=>r.runId===$('scenario').value),cfg=selected?.configuration;
 const cards=[];
 const card=(title,label,fields,description,src)=>{const c=el('article',undefined,'consumer');const top=el('div',undefined,'card-top');top.append(el('h3',title),el('span',label,'tag '+(label==='BLOCKED'?'warn':'neutral')));c.append(top,...fields.map(([k,v])=>row(k,v)),el('p',description));if(src)source(c,src);cards.push(c);return c;};
 const completion=data.pluginCompletion;
 if(completion?.trivy){
  const t=completion.trivy;
  const c=card('Trivy · 真实扫描准入',t.state,[['状态来源','HISTORICAL / 本轮只读快照'],['采集时间',time(completion.observedAt)],['阻塞',t.reason],['候选 OCI Index Digest',t.candidateDigest],['已扫描平台',t.targetPlatform],['Trivy 版本',t.toolVersion],['计划固定版本（未安装）',t.plannedToolVersion??'NOT_SELECTED'],['官方归档 SHA256（未下载）',t.plannedToolArchiveSha256??'UNAVAILABLE'],['候选拉取 HTTP',t.candidatePullStatus??'NOT_TESTED'],['DB Schema Version',t.dbVersion],['DB 更新时间',time(t.dbUpdatedAt)],['DB NextUpdate',time(t.dbNextUpdate)],['DB 新鲜度',t.dbFreshness],['本轮扫描次数',t.scanCount],['Policy','NOT_EVALUATED'],['Run / Digest','NONE']],t.requiredAuthorization,completion.source);
  const details=el('details');details.append(el('summary','13 插件完成度 · V2 范围（非生产 Gate）'));
  for(const p of completion.plugins){const d=el('details');d.append(el('summary',p.pluginId+' · '+p.EXECUTABLE));for(const key of ['REGISTERED','EXECUTABLE','MANAGED','SWITCHABLE','POLICY_INTEGRATED','ROUTED','VISIBLE','PORTABLE'])d.append(row(key,p[key]));d.append(el('p',p.gap));details.append(d);}c.append(details);
 }
 const liveSemgrep=liveCapabilities?.plugins.find(p=>p.pluginId==='semgrep');
 const admission=liveSemgrep?{state:liveSemgrep.state==='READY'?'READY / WEB_REAL':liveSemgrep.state,reason:liveSemgrep.reason??liveSemgrep.executionIdentity,observedAt:liveCapabilities.observedAt}:data.semgrepAdmission??{};
 const semgrepHistory=data.runs.flatMap(r=>r.plugins.filter(p=>p.pluginId==='semgrep'&&p.evidenceClass==='REAL'&&p.executionStatus==='COMPLETED').map(p=>({runId:r.runId,...p})));
 const semgrepCard=card('Semgrep · 当前执行准入',admission.state??'UNAVAILABLE',[
  ['新执行结果',liveSemgrep?.state==='READY'?'下方真实执行记录（REAL）':'NOT_EXECUTED'],['受限入口',admission.reason??'UNAVAILABLE'],
  ['已有真实历史',`PASS ${semgrepHistory.filter(p=>p.policyDecision==='PASS').length} / FAIL ${semgrepHistory.filter(p=>p.policyDecision==='FAIL').length}`],['准入采集时间',time(admission.observedAt)]],
  liveSemgrep?.state==='READY'?'专用受限 Linux 入口，固定 Clean / Finding；新结果见下方真实执行记录。Jenkins NOT_CONFIGURED，生产 NOT_ACTIVE。':liveSemgrep?.state==='DISABLED'?'当前非生产配置已禁用；执行账户与工具保留，重新启用后生效。':'历史 Runner / 规则 / Fixture 已开发，当前入口未获准或不可用。',admission.source);
 const semgrepNew=el('a','运行并查看 Semgrep REAL 结果');semgrepNew.href='#live-validation';semgrepCard.append(semgrepNew);
 const semgrepLink=el('a','查看历史 Semgrep Finding → FAIL');semgrepLink.href='#plugins';semgrepLink.addEventListener('click',()=>{if(data.runs.some(r=>r.runId==='attempt2-G-semgrep-fail')){$('scenario').value='attempt2-G-semgrep-fail';renderRun();}});semgrepCard.append(semgrepLink);
 const g=data.grafana??{};
 const grafanaCard=card('Grafana Dashboard',g.classification??'UNAVAILABLE',[
  ['Dashboard UID',g.uid],['已有面板',g.panelCount],['真实查询',g.realQuery],['导入状态',g.importState],['生产激活',g.productionActivation],
  ['有数据的查询面板',g.dataPanelCount==null?'NOT_TESTED':`${g.dataPanelCount} / ${g.queryPanelCount}（另有 1 个静态说明）`],
  ['已查回 Run ID',g.runId??'NOT_TESTED'],['Result Digest',g.resultDigest??'NOT_TESTED'],
  ['扫描执行时间',time(g.executionTime)],['查询验证时间',time(g.verifiedAt)]],
  g.importState==='VERIFIED'?'独立 Folder 中的八面板 Dashboard；已通过 Grafana 实际查询 Loki。同一真实受控扫描的历史归档重放，保留原执行时间，本轮未重新扫描。无数据的面板显示 No data；生产 Manager 未激活。':'复用既有八面板 Candidate，尚无已验证的导入或真实查询证据。',g.source);
 if(g.url){const a=el('a','打开 Grafana V2 Dashboard（需登录 Grafana）');a.href=g.url;grafanaCard.append(a);source(grafanaCard,g.querySource);}
 if(g.download){const a=el('a','打开既有 Dashboard JSON');a.href=g.download;grafanaCard.append(a);}
 for(const c of data.consumers??[])card(c.name+' Consumer',c.availability==='AVAILABLE'?'MOCK / CANDIDATE':'UNAVAILABLE',[
  ['协议回执',c.deliveryState],['真实远端投递',c.realRemoteDelivery],['生产投递数',c.productionDeliveryCount],['协议测试时间',time(c.timestamp)]],
  '此历史回执来自 HTTP 协议模拟，不代表真实远端投递。真实 Loki 查询见 Grafana 卡片，真实 Dojo 导入见独立治理卡片。',c.source);
 const dj=data.dojoReal??{};
 const dojoCard=card('DefectDojo · 真实漏洞治理',dj.state??'NOT_TESTED',[
  ['来源插件',dj.pluginId??'UNAVAILABLE'],['真实历史 Run ID',dj.runId??'UNAVAILABLE'],['原 Policy',dj.policyDecision??'UNAVAILABLE'],
  ['已映射 Finding',dj.findingCount??'UNAVAILABLE'],['原生严重级别 → Dojo 映射',dj.sourceSeverities?dj.sourceSeverities.join(', ')+' → '+dj.dojoSeverities.join(', '):'UNAVAILABLE'],
  ['Product / Engagement',dj.productId==null?'NOT_CREATED':`${dj.productId} / ${dj.engagementId}`],['Finding ID',dj.findingIds?.length?dj.findingIds.join(', '):'NOT_CREATED'],
  ['真实查询回验',dj.queryState??'NOT_TESTED'],['来源执行时间',time(dj.executionTime)],['本次核查时间',time(dj.observedAt)]],
  dj.state==='DELIVERED'?'真实历史 Semgrep Artifact 已导入独立 DEMO，并查询回两条 Finding。ERROR 是原生严重级别，High 是既有 Dojo 治理映射。同日志幂等重投未发送 HTTP；短期 Token 已撤销。':dj.reason==='DEVOPS_MANAGEMENT_AND_DEFECTDOJO_UNREACHABLE'?'DEMO 初始化已获批准；当前 devops SSH 与 DefectDojo HTTP 不可达，尚未执行远端初始化或创建 Token。未写入漏洞记录，生产健康暂时无法验证。':dj.state==='BLOCKED'?'已有真实 Semgrep Finding 已由现有 Consumer 离线映射；尚无隔离 DEMO 上下文与仅该范围可写的身份授权，因此未投递。下方历史 MOCK 回执不代表真实漏洞治理。':'尚未验证真实远端治理。',dj.source);
 if(dj.state==='DELIVERED')for(const [i,url]of(dj.findingUrls??[]).entries()){const a=el('a','打开 DefectDojo Finding #'+dj.findingIds[i]);a.href=url;dojoCard.append(a);}
 const sc=data.supplyChain??{};
 const supply=card('Supply Chain Security',sc.harborStatus??'UNAVAILABLE',[
  ['Harbor Candidate',sc.repository?sc.repository+':'+sc.tag:'UNAVAILABLE'],['Image Digest',sc.candidateDigest],
  ['镜像构建（HISTORICAL）',sc.build?sc.build.job+' #'+sc.build.number+' / '+sc.build.status:'UNAVAILABLE'],['GitLab Commit',sc.commit],
  ['Build Provenance',sc.provenance?.status],['Security Gate（HISTORICAL）',sc.securityGate?sc.securityGate.decision+' / '+sc.securityGate.mode+' / '+sc.securityGate.action:'UNAVAILABLE'],
  ['候选镜像 SBOM 绑定',sc.sbom?.candidateDigestBinding],['可用历史 SBOM',sc.sbom?sc.sbom.format+' '+sc.sbom.specVersion+' / '+sc.sbom.componentCount+' Maven 组件 / '+sc.sbom.status:'UNAVAILABLE'],
  ['候选 Cosign 签名',sc.signature?.status],['候选实际验签',sc.signature?.cosignVerification],['Release Approval',sc.releaseApproval?.status],
  ['Kubernetes Deployment',sc.deployment?.status],['只读采集时间',time(sc.observedAt)]],
  '候选构建、安全验收为两个独立历史 Job，通过精确 Digest 与 Commit 关联。143 个组件来自 #270 的历史 Maven SBOM，未证明是此候选镜像的内部 SBOM。独立 Cosign Fixture PASS 不用于此候选的签名或批准。',sc.source);
 if(sc.sbom){const details=el('details');details.append(el('summary','查看真实历史 SBOM 组件（前 '+sc.sbom.components.length+' / '+sc.sbom.componentCount+'，候选绑定 UNVERIFIED）'),el('p',sc.sbom.reason),row('SBOM SHA256',sc.sbom.sha256));
  for(const c of sc.sbom.components)details.append(el('p',c.name+' @ '+c.version),el('code',c.purl??'PURL_UNAVAILABLE'));supply.append(details);}
 if(sc.sbom?.bindingReview){const br=sc.sbom.bindingReview,details=el('details');details.append(el('summary','SBOM Digest 关联核查：'+br.status),
  row('候选构建 JAR SHA256',br.candidateJarSha256),row('历史 SBOM SHA256',br.sbomSha256),row('候选构建完成',time(br.candidateBuildCompletedAt)),row('历史 SBOM 生成',time(br.sbomGeneratedAt)),
  row('插件执行入口',br.pluginRunner),row('网页 SBOM 开关',br.webSwitch),el('p','现有 Core 的全局/单插件关闭路径已验证零扫描、零求值；SBOM 真实执行接线仍为 INCOMPLETE。'));
  for(const gap of br.missingEvidence)details.append(el('p','缺失：'+gap));source(details,br.source);supply.append(details);}
 if(sc.deployment)supply.append(row('当前运行 Image ID',sc.deployment.runningImageIds.join(' · ')));
 for(const link of sc.links??[]){const a=el('a',link.label);a.href=link.url;supply.append(a);}
 const ci=data.ciCd??{};
 const chain=card('Jenkins / GitOps 闭环',ci.availability==='UNAVAILABLE'?'UNAVAILABLE':'HISTORICAL / REAL',[
  ['构建',ci.build==null?'UNAVAILABLE':'#'+ci.build+' SUCCESS'],['同次 Run ID',ci.runId],['Policy',ci.policyDecision],['实际变化',ci.updatedValue&&ci.restoredValue?ci.updatedValue+' → '+ci.restoredValue:'UNAVAILABLE'],['完成时间',time(ci.completedAt)]],
  '同次真实闭环来自既有 #6；本轮未重新触发。完整 Commit、Argo Revision 与原始链接见下方 Pipeline Overview。',ci.source);
 if(ci.buildUrl){const a=el('a','打开实际 Jenkins Build');a.href=ci.buildUrl;chain.append(a);}
 const configCard=card('Candidate Summary / Policy',cfg?'HISTORICAL':'UNAVAILABLE',[
  ['Run ID',selected?.runId],['配置',cfg?`${cfg.enabled?'ENABLED':'DISABLED'} / ${cfg.globalMode}`:'UNAVAILABLE'],['Policy',cfg?`${cfg.policyVersion} / ${cfg.securityLevel} / ${cfg.profile}`:'UNAVAILABLE'],['原综合判定',selected?.overallDecision],['Artifact 文件数',selected?.artifact?.fileCount]],
  '读取原 Summary、原 Policy Decision 和 seal；不重新求值，不把 Disabled / Error / Blocked 改成 PASS。',cfg?.source);
 const a=el('a','查看统一只读 API');a.href='/api/overview';configCard.append(a);
 $('candidate-components').replaceChildren(...cards);
 $('registry-scope').textContent=cfg?`HISTORICAL / REPLAY · ${selected.runId} · ${cfg.profile} · ${cfg.policyVersion} · 当前读到的 Registry 定义不等于获准在线执行。`:'UNAVAILABLE：所选记录缺少已验证配置，不能推断开关。';
 $('registry-rows').replaceChildren(...(data.registry?.entries??[]).map(p=>{
  const tr=el('tr');const name=el('td');name.append(el('strong',p.pluginId),el('div',p.runner+' · '+p.executionMode,'muted'));tr.append(name);
  const enabled=cfg?.plugins?.[p.pluginId]?.enabled;const flag=el('td');if(typeof enabled==='boolean'){const input=el('input');input.type='checkbox';input.checked=enabled;input.disabled=true;input.setAttribute('aria-label',p.pluginId+' historical enabled');flag.append(input,el('span',enabled?' ENABLED':' DISABLED'));}else flag.textContent='UNAVAILABLE';tr.append(flag);
  const saved=selected?.artifact?.statuses?.[p.pluginId];tr.append(el('td',saved?`${saved.executionStatus} / ${saved.policyDecision??'未求值'}`:'NOT_TESTED'));
  const live=liveCapabilities?.plugins.find(x=>x.pluginId===p.pluginId);tr.append(el('td',live?live.state+' · '+(live.reason??live.executionIdentity??'已配置受限入口')+' · '+(p.pluginId==='gitleaks'?'Jenkins #6 HISTORICAL':'Jenkins NOT_CONFIGURED')+' · Production NOT_ACTIVE':'NOT_CONFIGURED · 无页面执行入口'));return tr;
 }));
 $('registry-source').replaceChildren();source($('registry-source'),data.registry?.source);if(cfg)source($('registry-source'),cfg.source);
}
function render(){
  const selected=$('scenario').value;
  $('scenario').replaceChildren(...data.runs.map(r=>{const o=el('option',r.label+(r.availability==='UNAVAILABLE'?' · UNAVAILABLE':''));o.value=r.runId;return o;}));
  if(data.runs.some(r=>r.runId===selected))$('scenario').value=selected;
  $('scenario').disabled=false;
  $('production').textContent=data.baseline.PRODUCTION_SECURITY_MANAGER??'UNAVAILABLE';
  $('runtime').textContent=data.baseline.FINAL_WIRED_CAPABILITY??'UNAVAILABLE';
  $('integrity').textContent=data.baseline.ORIGINAL_EVIDENCE_INTEGRITY??'UNAVAILABLE';
  renderRun();$('consumer-grid').replaceChildren();
  for(const c of data.consumers){const card=el('article',undefined,'consumer');const top=el('div',undefined,'card-top');top.append(el('h3',c.name),el('span','MOCK','tag mock'));card.append(top,el('div',c.deliveryState??'UNAVAILABLE','delivery'),el('p','历史回执 · 不向真实远端投递'));
    card.append(row('Router',c.routerState),row('记录 Run ID',c.runId),row('真实远端投递',c.realRemoteDelivery),row('生产投递数',c.productionDeliveryCount),row('HTTP 状态',c.httpStatus),row('记录时间',time(c.timestamp)));
    const details=el('details');details.append(el('summary','查看投递证据来源'));source(details,c.source);if(c.receiptDigest)details.append(el('p','Receipt digest: '+c.receiptDigest));if(c.reason)details.append(el('p',c.reason));card.append(details);$('consumer-grid').append(card);}
  const limits=[['Trivy Runtime',data.baseline.TRIVY_RUNTIME_FACT_CAPTURE],['DefectDojo Candidate HTTP / 真实投递',`${data.dojo.httpAdapter} / ${data.dojo.realDelivery}`],['DefectDojo Runtime',data.baseline.DEFECTDOJO_RUNTIME_FACT_CAPTURE],['Jenkins V2 Real CI',data.baseline.JENKINS_REAL_CI],['Grafana V2 真实查询',data.grafana?.realQuery??data.baseline.GRAFANA_REAL_QUERY],['Summary V2 Migration',data.baseline.SUMMARY_V2_MIGRATION]];
  $('limits').replaceChildren(...limits.map(([name,value])=>{const r=el('div',undefined,'limit');r.append(el('strong',name),el('span',value??'UNAVAILABLE'));return r;}));
  $('read-at').textContent='本页读取时间 '+time(data.servedAt);
}
async function load(){
  $('refresh').disabled=true;
  try{const r=await fetch('/api/overview',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);data=await r.json();render();$('error').hidden=true;}
  catch(e){$('error').hidden=false;$('error').textContent='UNAVAILABLE：证据读取失败。'+e.message+'。下方若保留上次结果，其读取时间仍以页脚为准。';}
  finally{$('refresh').disabled=false;}
}
$('scenario').addEventListener('change',renderRun);$('refresh').addEventListener('click',load);load();
let sbomProjectSession=null,projectSessions=[],projectState=null;
const projectPanel=el('div',undefined,'consumer'),projectLabel=el('label','SBOM 项目 '),projectSelect=el('select'),projectEnabled=el('input'),projectSave=el('button','保存本项目 SBOM 开关'),projectInfo=el('p');
projectSelect.id='sbom-project';projectEnabled.type='checkbox';projectEnabled.id='project-sbom-enabled';projectSave.type='button';projectLabel.append(projectSelect);projectPanel.append(el('h3','项目级 SBOM 管理'),projectLabel,el('label',' 本项目 SBOM '),projectEnabled,projectSave,projectInfo);$('control-rows').closest('.registry-table-wrap').before(projectPanel);
const ciPanel=el('div',undefined,'consumer'),ciFlag=el('input'),ciSave=el('button','保存 CI 项目 Gitleaks 开关'),ciInfo=el('p');let ciProjectState=null;ciFlag.type='checkbox';ciSave.type='button';ciPanel.append(el('h3','CI 项目 · python-fixture'),el('p','仅允许已授权流水线调用固定 Gitleaks Clean；触发源码信息不代表扫描 GitLab checkout。'),ciFlag,ciSave,ciInfo);projectPanel.after(ciPanel);
async function loadCIProject(){try{ciProjectState=await api('/api/projects/python-fixture/config');ciFlag.checked=ciProjectState.sbomEnabled;ciSave.disabled=false;ciInfo.textContent='gitleaks · '+(ciProjectState.effectiveEnabled?'ENABLED':'DISABLED')+' · '+ciProjectState.source+' · '+ciProjectState.securityLevel;}catch{ciSave.disabled=true;ciInfo.textContent='本机操作员授权后可管理此 CI 项目。';}}
ciSave.addEventListener('click',async()=>{if(!ciProjectState)return;try{await api('/api/projects/python-fixture/config',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionToken},body:JSON.stringify({revision:ciProjectState.revision,sbomEnabled:ciFlag.checked})});await loadControls();await loadCIProject();}catch(e){ciInfo.textContent=e.message;}});
async function loadProjectControls(){
 if(!sbomProjectSession){projectSave.disabled=true;projectEnabled.disabled=true;projectInfo.textContent='本机操作员授权：在仓库运行 node infra/security/manager-v2/view/control.mjs open。长期凭据只保存在受保护文件；登录票据一次有效、30 秒失效。';return;}
 projectState=await api('/api/projects/'+sbomProjectSession.projectId+'/config');projectEnabled.disabled=false;projectEnabled.checked=projectState.sbomEnabled;projectSave.disabled=false;projectInfo.textContent=projectState.projectId+' · 项目开关 '+(projectState.sbomEnabled?'ON':'OFF')+' · 实际 '+(projectState.effectiveEnabled?'ENABLED':'DISABLED')+' · '+projectState.source+' · '+projectState.securityLevel;
}
projectSelect.addEventListener('change',async()=>{sbomProjectSession=projectSessions.find(p=>p.projectId===projectSelect.value)??null;try{await loadProjectControls();liveCapabilities=await api('/api/plugins');await refreshLive();capabilityText();}catch(e){projectInfo.textContent=e.message;}});
projectSave.addEventListener('click',async()=>{if(!sbomProjectSession||!projectState)return;try{await api('/api/projects/'+sbomProjectSession.projectId+'/config',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionToken},body:JSON.stringify({revision:projectState.revision,sbomEnabled:projectEnabled.checked})});await loadProjectControls();liveCapabilities=await api('/api/plugins');capabilityText();}catch(e){projectInfo.textContent=e.message;}});
let sessionToken=null,liveCapabilities=null,liveBusy=false,currentConfig=null,latestRuns=[];
async function api(url,options){const r=await fetch(url,{cache:'no-store',...options,headers:{...(sbomProjectSession?{'X-Project-Token':sbomProjectSession.projectToken}:{}),...options?.headers}});const v=await r.json();if(!r.ok)throw Error(v.error??v.reason??'HTTP '+r.status);return v;}
function capabilityText(){
 const c=liveCapabilities?.plugins.find(p=>p.pluginId===$('live-plugin').value);
 $('live-capability').textContent=c?[c.pluginId+': '+c.state,c.reason,c.executionHost,c.executionIdentity,'工具版本：'+(c.toolVersion??'未验证')].filter(Boolean).join(' · '):'UNAVAILABLE';
 const selected=$('live-scenario').value;
 $('live-scenario').replaceChildren(...(c?.scenarios??[]).map(id=>{const o=el('option',c?.pluginId==='cosign'?(id==='clean'?'Valid Signature':'Invalid / Tampered Signature'):(id==='clean'?'Clean':'Controlled Finding'));o.value=id;return o;}));
 if(c?.scenarios.includes(selected))$('live-scenario').value=selected;
 $('run-validation').disabled=liveBusy||c?.state!=='READY'||(c?.pluginId==='sbom'&&!sbomProjectSession);if(c?.pluginId==='sbom')$('live-capability').textContent+=' · 当前项目：'+(sbomProjectSession?.projectId??'尚未授权');
 renderCandidate();
}
function renderLive(runs){
 const comparison=['gitleaks','semgrep','cosign'].flatMap(id=>['clean','controlled-finding'].map(s=>runs.find(r=>r.pluginId===id&&r.scenarioId===s&&r.evidenceClass==='REAL'&&r.state==='COMPLETED'))).filter(Boolean);
 const matrix=el('article',undefined,'consumer');matrix.id='three-plugin-real-status';
 matrix.append(el('h3','三个插件 · 真实受控执行'),el('p','仅从已完成的 REAL 记录读取判定；各记录时间、Run ID 与摘要见下方。生产 NOT_ACTIVE。'));
 const table=el('table');const head=el('tr');for(const label of ['Plugin','Clean / Valid','Finding / Invalid','当前入口'])head.append(el('th',label));table.append(head);
 for(const id of ['gitleaks','semgrep','cosign']){const tr=el('tr');tr.append(el('td',id));for(const scenario of ['clean','controlled-finding']){const result=comparison.find(r=>r.pluginId===id&&r.scenarioId===scenario);const cell=el('td',result?'REAL / '+result.policyDecision:'NOT_TESTED');if(result)cell.title=result.runId+' · '+time(result.scannerCompletedAt);tr.append(cell);}tr.append(el('td',liveCapabilities?.plugins.find(p=>p.pluginId===id)?.state??'UNAVAILABLE'));table.append(tr);}
 matrix.append(table);
 $('live-results').replaceChildren(matrix,...[...comparison,...runs.filter(r=>!comparison.includes(r))].map(r=>{
 const card=el('article',undefined,'consumer');card.dataset.runId=r.runId;
 const label=r.pluginId==='cosign'?'Cosign '+(r.scenarioId==='clean'?'Valid':'Invalid / Tampered'):r.pluginId==='gitleaks'?'Gitleaks '+(r.scenarioId==='clean'?'Clean':'Finding'):r.pluginId+' / '+r.scenarioId;
 const top=el('div',undefined,'card-top');top.append(el('h3',label),el('span',r.evidenceClass,'tag '+(r.evidenceClass==='REAL'?'real':'neutral')));
 card.append(top,el('div',r.state,'delivery'),row('Policy Decision',r.policyDecision??'未求值'),row('Run ID',r.runId),row('开始',time(r.scannerStartedAt??r.startedAt)),row('完成',time(r.scannerCompletedAt??r.completedAt)),row('耗时',r.durationMs==null?'—':r.durationMs+' ms'),row('Policy 求值次数',r.evaluationCount??0),row('实际 Security Level',r.securityLevel??'standard（历史固定）'),row('配置 Revision',r.configurationSnapshot?.revision??'历史配置'),row('配置来源',r.configurationSnapshot?.source?.kind??'HISTORICAL'));
 if(r.ciContext){card.append(row('CI Project',r.ciContext.projectId),row('CI Provider',r.ciContext.ciProvider),row('Source Repository',r.ciContext.sourceRepository),row('Commit SHA',r.ciContext.commitSha),row('Job / Build',r.ciContext.jobId+' #'+r.ciContext.buildId),row('Trigger',r.ciContext.trigger),row('扫描范围',r.ciContext.sourceScope));const link=el('a','打开对应 Jenkins 构建');link.href=r.ciContext.buildUrl;card.append(link);}
 if(r.executionDiagnostic?.stages)card.append(row('真实执行诊断',r.executionDiagnostic.reason),row('阶段证据',r.executionDiagnostic.stages.map(s=>s.stage+' @ '+time(s.time)+(s.pid?' · PID '+s.pid:'')+(s.errorCategory?' · '+s.errorCategory:'')).join(' → ')));
 if(r.sourceMode)card.append(row('SOURCE_MODE',r.sourceMode),row('Source Snapshot SHA256',r.sourceSnapshotSha256),row('扫描 Commit',r.sourceCommitSha),row('Git Tree',r.sourceTreeOid),row('扫描文件数',r.sourceFileCount),row('扫描总字节数',r.sourceExpandedBytes),row('项目预算例外',JSON.stringify(r.sourceBudgetExceptionHits??[])),row('源码快照清理',r.sourceCleanup));
 if(r.scannerExecuted===true)card.append(row('执行主机',r.executionHost),row('执行身份',r.executionIdentity),row('扫描工具',r.toolVersion),row('退出码',r.scannerExitCode));
 if(r.pluginId==='sbom'){
  card.append(row('Project ID',r.projectId),row('记录来源',r.evidenceClass==='REAL'?'HISTORICAL · 已完成的真实受控执行':'NOT_TESTED · 未完成真实生成'),row('Runner',r.executionIdentity),row('工具版本',r.toolVersion),row('生成退出码',r.scannerExitCode),row('Result Router',(r.router??[]).map(x=>x.consumerId+': '+x.deliveryDecision).join(' / ')||'NOT_TESTED'),row('Source Artifact SHA256',r.sourceArtifactSha256),row('SBOM SHA256',r.sbomSha256),row('格式',r.sbomFormat?r.sbomFormat+' '+r.sbomSpecVersion:'NOT_GENERATED'),row('实际组件数',r.componentCount),row('范围',r.scope),el('p','固定非生产应用依赖 Fixture；不关联任何 Harbor 候选镜像。'));
  if(r.executionDiagnostic){const diagnostic=el('details');diagnostic.append(el('summary','执行诊断（退出码 / 阶段 / 清理）'),el('pre',JSON.stringify(r.executionDiagnostic,null,2)));card.append(diagnostic);}
  if(r.state==='COMPLETED'){const button=el('button','读取原始 SBOM / 展开组件');button.type='button';button.addEventListener('click',async()=>{try{const response=await fetch('/api/projects/'+encodeURIComponent(r.projectId)+'/runs/'+r.runId+'/sbom',{cache:'no-store',headers:{'X-Project-Token':sbomProjectSession.projectToken}});if(!response.ok)throw Error('SBOM_DOWNLOAD_'+response.status);const raw=await response.text(),bom=JSON.parse(raw);const d=el('details');d.open=true;d.append(el('summary','CycloneDX · '+bom.components.length+' 个真实组件'));for(const c of bom.components)d.append(el('p',c.name+' @ '+c.version),el('code',c.purl??'PURL_UNAVAILABLE'));const download=el('a','下载本次 CycloneDX JSON');const objectUrl=URL.createObjectURL(new Blob([raw],{type:'application/json'}));download.href=objectUrl;download.download=r.runId+'-sbom.json';d.append(download);card.append(d);button.disabled=true;}catch(e){button.textContent='读取失败：'+e.message;}});card.append(button);}
 }
 if(r.pluginId==='trivy'){
  card.append(row('Project ID',r.projectId),row('记录来源',r.evidenceClass==='REAL'?'已完成的真实受控执行':'NOT_TESTED · 未完成真实扫描'),row('执行身份',r.executionIdentity),row('工具版本',r.toolVersion),row('工具 SHA256',r.toolSha256),row('漏洞条数',r.findingCount),row('候选 Index Digest',r.indexDigest),row('Platform Digest',r.platformDigest),row('Result Router',(r.router??[]).map(x=>x.consumerId+': '+x.deliveryDecision).join(' / ')||'NOT_TESTED'),el('p','固定非生产 Harbor 候选镜像；漏洞库新鲜度与拉取凭据由远端受限入口强制校验。'));
  if(r.executionDiagnostic){const diagnostic=el('details');diagnostic.append(el('summary','执行诊断（远端门禁）'),el('pre',JSON.stringify(r.executionDiagnostic,null,2)));card.append(diagnostic);}
 }
 if(r.pluginId==='kyverno'){
  card.append(row('Project ID',r.projectId),row('Case',r.caseId),row('准入结果',r.allowed===true?'ALLOWED':r.allowed===false?'DENIED':'—'),row('Kyverno 策略',r.policyName),row('命名空间',r.namespace),row('镜像',r.image),row('Result Router',(r.router??[]).map(x=>x.consumerId+': '+x.deliveryDecision).join(' / ')||'NOT_TESTED'),el('p','固定非生产准入探针；clean=合规放行，controlled-finding=违规被拒。'));
 }
 if(r.pluginId==='cosign'&&r.scannerExecuted===true)card.append(row('验签范围','受控离线 Blob，非生产镜像信任'),row('验签结果',r.verificationStatus),row('被验证对象 Digest',r.verifiedObjectDigest),row('受控公钥 Digest',r.trustPublicKeyDigest),row('验签输出',r.verificationReason));
 if(Number.isSafeInteger(r.findingsCount))card.append(row('实际命中',r.findingsCount));
 if(r.findingRules?.length)card.append(row('检测规则',r.findingRules.join(', ')));
 if(r.evidenceClass==='REAL'&&r.scenarioId==='controlled-finding'&&r.policyDecision==='FAIL')card.append(el('p',r.pluginId==='cosign'?'固定篡改材料验签被拒绝。FAIL 是预期的安全判定，执行器正常完成。':'检测到受控 Finding。FAIL 是预期的策略判定，扫描正常完成。'));
 if(r.reason)card.append(el('p','原因：'+r.reason));
 if(r.resultDigest)card.append(el('span',r.evidenceClass==='REAL'?'Result Digest':'预检 Result Digest','detail-label'),el('code',r.resultDigest));
 if(r.lokiDelivery){const l=r.lokiDelivery;
  card.append(row('Loki 自动投递',l.state),row('Loki Push',l.pushHttpStatus??l.pushState??'NOT_SENT'),row('同 Run 查询',l.queryState),row('查询时间',time(l.queryAt)));
  if(l.reason)card.append(row('投递原因',l.reason));
  if(l.grafanaUrl?.startsWith('http://grafana.devops.local/d/security-manager-v2-candidate/')){const a=el('a','在 Grafana 查看此次 Run');a.href=l.grafanaUrl;card.append(a);}
 }else card.append(row('本轮自动 Loki 投递','NOT_TESTED（历史记录）'));
 for(const l of r.lokiReplayEvents??[]){
  const audit=el('section',undefined,'consumer');
  audit.append(el('h4','历史真实结果 · 后续补投（非新扫描）'),row('补投状态',l.state),row('同 Run 查询',l.queryState),row('Policy（原判定）',l.policyDecision),row('Run ID',l.runId),row('Result Digest（原摘要）',l.resultDigest),row('补投时间',time(l.deliveryAt)),row('回查时间',time(l.queryAt)),row('回执 Digest',l.receiptDigest));
  if(l.grafanaUrl?.startsWith('http://grafana.devops.local/d/security-manager-v2-candidate/')){const a=el('a','在 Grafana 查看历史补投记录');a.href=l.grafanaUrl;audit.append(a);}
  card.append(audit);
 }
 if(r.auditDigest)card.append(el('p','Audit Digest: '+r.auditDigest));
 if(r.source)card.append(el('code',r.source,'source-path'));else card.append(el('p','没有已验证的扫描报告或 Policy Result。'));
 return card;
}));}
async function refreshLive(){const v=await api('/api/runs');latestRuns=v.runs;renderLive(v.runs);renderControls();}
async function initializeLive(){try{
 const catalog=await api('/api/sbom/projects');try{projectSessions=(await api('/api/sbom/session')).projects;}catch{projectSessions=[];}
 projectSelect.replaceChildren(...catalog.projects.map(p=>{const o=el('option',p.displayName+' · '+p.projectId);o.value=p.projectId;return o;}));sbomProjectSession=projectSessions.find(p=>p.projectId===projectSelect.value)??null;
 const sbomOption=el('option','SBOM · CycloneDX');sbomOption.value='sbom';$('live-plugin').append(sbomOption);const trivyOption=el('option','Trivy · 镜像漏洞');trivyOption.value='trivy';$('live-plugin').append(trivyOption);const kyvernoOption=el('option','Kyverno · 集群准入');kyvernoOption.value='kyverno';$('live-plugin').append(kyvernoOption);liveCapabilities=await api('/api/plugins');sessionToken=liveCapabilities.csrfToken;await refreshLive();try{await loadControls();}catch{$('controls-message').textContent='全局管理需要本机操作员授权。';}await loadProjectControls();await loadCIProject();capabilityText();
 }catch(e){$('live-message').textContent='UNAVAILABLE: '+e.message;}}
$('live-plugin').addEventListener('change',capabilityText);
$('run-validation').addEventListener('click',async()=>{
 if(liveBusy||!sessionToken)return;liveBusy=true;$('run-validation').disabled=true;$('live-message').textContent='正在提交并检查固定 Runner 执行条件…';
 try{const r=await api('/api/run',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionToken},body:JSON.stringify({pluginId:$('live-plugin').value,scenarioId:$('live-scenario').value,...($('live-plugin').value==='sbom'?{projectId:sbomProjectSession.projectId}:{}),...($('live-plugin').value==='trivy'?{projectId:liveCapabilities?.plugins.find(p=>p.pluginId==='trivy')?.projects?.[0]}:{}),...($('live-plugin').value==='kyverno'?{projectId:liveCapabilities?.plugins.find(p=>p.pluginId==='kyverno')?.projects?.[0]}:{})})});
  let done=false;const maxPolls=$('live-plugin').value==='trivy'?480:190;for(let i=0;i<maxPolls;i++){const v=await api('/api/runs/'+r.runId);if(!['QUEUED','RUNNING'].includes(v.state)){$('live-message').textContent=`${v.state}: ${v.reason??v.policyDecision??'无判定'} · ${v.runId}`;done=true;break;}await new Promise(r=>setTimeout(r,500));}
  if(!done)$('live-message').textContent='执行状态未能及时确认，请刷新记录；不会自动重复执行。';await refreshLive();
 }catch(e){$('live-message').textContent='请求失败：'+e.message;}
 finally{liveBusy=false;capabilityText();}
});
function renderControls(){
 if(!currentConfig)return;
 const s=currentConfig.settings;
 $('control-enabled').checked=s.enabled;$('control-level').value=s.securityLevel;
 $('control-rows').replaceChildren(...['gitleaks','semgrep','cosign','sbom','trivy','kyverno'].map(id=>{
  const tr=el('tr');tr.append(el('td',id));const cell=el('td'),input=el('input');input.type='checkbox';input.id='control-'+id;input.checked=s.plugins[id].enabled;input.setAttribute('aria-label',id+' candidate enabled');cell.append(input,el('span',s.plugins[id].enabled?' ENABLED':' DISABLED'));tr.append(cell);
  tr.append(el('td',currentConfig.source.kind+' · '+(!s.enabled?'MASTER_DISABLED':!s.plugins[id].enabled?'PLUGIN_DISABLED':'ENABLED')));
  const last=latestRuns.find(r=>r.pluginId===id&&r.evidenceClass==='REAL'&&r.state==='COMPLETED');tr.append(el('td',last?last.policyDecision+' / '+(last.securityLevel??'standard')+' · '+time(last.scannerCompletedAt)+' · '+last.runId:'NOT_TESTED'));return tr;
 }));
 $('effective-controls').textContent=JSON.stringify({scope:currentConfig.scope,revision:currentConfig.revision,updatedAt:currentConfig.updatedAt,settings:s,source:currentConfig.source,configurationOrigins:currentConfig.effectiveConfig.configurationOrigins,effectiveSecurityLevel:currentConfig.effectiveConfig.effectiveSecurityLevel,appliedOverrides:currentConfig.effectiveConfig.appliedOverrides,effectivePolicy:Object.fromEntries(['gitleaks','semgrep','cosign','sbom','trivy','kyverno'].map(id=>[id,currentConfig.effectiveConfig.effectivePolicy[id]])),history:currentConfig.history},null,2);
 $('save-controls').disabled=false;$('reset-controls').disabled=false;
}
async function loadControls(){currentConfig=await api('/api/config');renderControls();await loadProjectControls();$('controls-message').textContent='已加载 Revision '+currentConfig.revision+' · '+(currentConfig.updatedAt?time(currentConfig.updatedAt):'演示默认配置')+' · 生产 NOT_ACTIVE';}
async function saveControls(reset=false){
 if(!currentConfig||!sessionToken||liveBusy)return;
 const settings={enabled:$('control-enabled').checked,securityLevel:$('control-level').value,plugins:Object.fromEntries(['gitleaks','semgrep','cosign','sbom','trivy','kyverno'].map(id=>[id,{enabled:$('control-'+id).checked}]))};
 $('save-controls').disabled=true;$('reset-controls').disabled=true;
 try{currentConfig=await api(reset?'/api/config/reset':'/api/config',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionToken},body:JSON.stringify(reset?{revision:currentConfig.revision}:{revision:currentConfig.revision,settings})});renderControls();liveCapabilities=await api('/api/plugins');sessionToken=liveCapabilities.csrfToken;capabilityText();$('controls-message').textContent='保存成功 · Revision '+currentConfig.revision+' · '+time(currentConfig.updatedAt)+' · 下次受控验证生效';}
 catch(e){$('controls-message').textContent='保存失败：'+e.message+'。未确认生效，请重新读取配置。';}
 finally{$('save-controls').disabled=false;$('reset-controls').disabled=false;}
}
$('control-form').addEventListener('submit',e=>{e.preventDefault();saveControls();});
$('reset-controls').addEventListener('click',()=>saveControls(true));
initializeLive();
