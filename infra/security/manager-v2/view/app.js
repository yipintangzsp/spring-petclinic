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
    card.append(top,el('p',{gitleaks:'凭据泄漏检测 / 受控目录',semgrep:'代码规则检测 / 受控源码',cosign:'离线 Blob 验签 / 非生产信任验证'}[p.pluginId],'plugin-sub'));
    const decision=p.policyDecision??(p.executionStatus==='DISABLED'?'DISABLED':p.executionStatus??'UNAVAILABLE');
    card.append(el('div',decision,'decision '+(p.policyDecision==='PASS'?'pass-text':p.policyDecision==='FAIL'?'fail-text':'off-text')),el('p',p.policyDecision?'原始 Policy Decision':'未产生 Policy Decision','decision-label'));
    const execution=el('div',undefined,'execution');execution.append(el('span',p.executionStatus??'UNAVAILABLE','tag neutral'),el('span','REPLAY','tag replay'));card.append(execution);
    card.append(row('插件配置',p.enabled===true?'ENABLED':p.enabled===false?'DISABLED':'UNAVAILABLE'),row('旧 Gate',p.oldGateDecision),row('Policy 求值次数',p.evaluationCount),row('执行完成',time(p.completedAt)));
    const d=el('div',undefined,'digest');d.append(el('span','RESULT DIGEST','detail-label'),el('code',p.resultDigest??'UNAVAILABLE'));card.append(d);
    const details=el('details');details.append(el('summary','证据与执行范围'));
    for(const [key,value] of [['范围',p.executionScope],['Raw report SHA-256',p.rawReportDigest],['Fact digest',p.factDigest],['校验',p.integrity],['原因',p.failureReason??p.reason]])if(value)details.append(el('p',`${key}: ${value}`));
    source(details,p.source);card.append(details);$('plugin-grid').append(card);
  }
  $('source').replaceChildren();source($('source'),r.source);
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
  const limits=[['Trivy Runtime',data.baseline.TRIVY_RUNTIME_FACT_CAPTURE],['DefectDojo Candidate HTTP / 真实投递',`${data.dojo.httpAdapter} / ${data.dojo.realDelivery}`],['DefectDojo Runtime',data.baseline.DEFECTDOJO_RUNTIME_FACT_CAPTURE],['Jenkins V2 Real CI',data.baseline.JENKINS_REAL_CI],['Grafana V2 真实查询',data.baseline.GRAFANA_REAL_QUERY],['Summary V2 Migration',data.baseline.SUMMARY_V2_MIGRATION]];
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
let sessionToken=null,liveCapabilities=null,liveBusy=false;
async function api(url,options){const r=await fetch(url,{cache:'no-store',...options});const v=await r.json();if(!r.ok)throw Error(v.error??v.reason??'HTTP '+r.status);return v;}
function capabilityText(){
 const c=liveCapabilities?.plugins.find(p=>p.pluginId===$('live-plugin').value);
 $('live-capability').textContent=c?[c.pluginId+': '+c.state,c.reason,c.executionHost,c.executionIdentity,'工具版本：'+(c.toolVersion??'未验证')].filter(Boolean).join(' · '):'UNAVAILABLE';
 const selected=$('live-scenario').value;
 $('live-scenario').replaceChildren(...(c?.scenarios??[]).map(id=>{const o=el('option',id==='clean'?'Clean':'Controlled Finding');o.value=id;return o;}));
 if(c?.scenarios.includes(selected))$('live-scenario').value=selected;
 $('run-validation').disabled=liveBusy||c?.state!=='READY';
}
function renderLive(runs){
 const comparison=['clean','controlled-finding'].map(s=>runs.find(r=>r.pluginId==='gitleaks'&&r.scenarioId===s&&r.evidenceClass==='REAL'&&r.state==='COMPLETED')).filter(Boolean);
 $('live-results').replaceChildren(...[...comparison,...runs.filter(r=>!comparison.includes(r))].map(r=>{
 const card=el('article',undefined,'consumer');card.dataset.runId=r.runId;
 const label=r.pluginId==='gitleaks'?'Gitleaks '+(r.scenarioId==='clean'?'Clean':'Finding'):r.pluginId+' / '+r.scenarioId;
 const top=el('div',undefined,'card-top');top.append(el('h3',label),el('span',r.evidenceClass,'tag '+(r.evidenceClass==='REAL'?'real':'neutral')));
 card.append(top,el('div',r.state,'delivery'),row('Policy Decision',r.policyDecision??'未求值'),row('Run ID',r.runId),row('开始',time(r.scannerStartedAt??r.startedAt)),row('完成',time(r.scannerCompletedAt??r.completedAt)),row('耗时',r.durationMs==null?'—':r.durationMs+' ms'),row('Policy 求值次数',r.evaluationCount??0));
 if(r.scannerExecuted===true)card.append(row('执行主机',r.executionHost),row('执行身份',r.executionIdentity),row('Gitleaks',r.toolVersion),row('退出码',r.scannerExitCode));
 if(Number.isSafeInteger(r.findingsCount))card.append(row('实际命中',r.findingsCount));
 if(r.findingRules?.length)card.append(row('检测规则',r.findingRules.join(', ')));
 if(r.evidenceClass==='REAL'&&r.scenarioId==='controlled-finding'&&r.policyDecision==='FAIL')card.append(el('p','检测到受控假凭证。FAIL 是预期的策略判定，扫描正常完成。'));
 if(r.reason)card.append(el('p','原因：'+r.reason));
 if(r.resultDigest)card.append(el('span',r.evidenceClass==='REAL'?'Result Digest':'预检 Result Digest','detail-label'),el('code',r.resultDigest));
 if(r.auditDigest)card.append(el('p','Audit Digest: '+r.auditDigest));
 if(r.source)card.append(el('code',r.source,'source-path'));else card.append(el('p','没有已验证的扫描报告或 Policy Result。'));
 return card;
}));}
async function refreshLive(){const v=await api('/api/runs');renderLive(v.runs);}
async function initializeLive(){try{liveCapabilities=await api('/api/plugins');sessionToken=liveCapabilities.csrfToken;await refreshLive();capabilityText();}catch(e){$('live-message').textContent='UNAVAILABLE: '+e.message;}}
$('live-plugin').addEventListener('change',capabilityText);
$('run-validation').addEventListener('click',async()=>{
 if(liveBusy||!sessionToken)return;liveBusy=true;$('run-validation').disabled=true;$('live-message').textContent='正在提交并检查固定 Runner 执行条件…';
 try{const r=await api('/api/run',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionToken},body:JSON.stringify({pluginId:$('live-plugin').value,scenarioId:$('live-scenario').value})});
  let done=false;for(let i=0;i<65;i++){const v=await api('/api/runs/'+r.runId);if(!['QUEUED','RUNNING'].includes(v.state)){$('live-message').textContent=`${v.state}: ${v.reason??v.policyDecision??'无判定'} · ${v.runId}`;done=true;break;}await new Promise(r=>setTimeout(r,500));}
  if(!done)$('live-message').textContent='执行状态未能及时确认，请刷新记录；不会自动重复执行。';await refreshLive();
 }catch(e){$('live-message').textContent='请求失败：'+e.message;}
 finally{liveBusy=false;capabilityText();}
});
initializeLive();
