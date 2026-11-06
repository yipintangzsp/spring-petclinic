// Read-only, allowlisted projection. No scanner, policy evaluation or consumer execution.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {verifyResult} from '../result.mjs';
import {realThreePluginsRegistry} from '../registry.mjs';
import {digest} from '../../summary-v2/codec.mjs';
export const root = fileURLToPath(new URL('../../../../', import.meta.url));
const evidence = 'evidence/2026-11-05/';
const runs = evidence + 'security-manager-v2-cosign-real/real-linux/outputs/';
export const catalog = [
  ['attempt2-P-service-project', '最近三插件完整执行 · Service 项目'],
  ['attempt2-Q-cross-project-identity-rejected', '最近执行 · 跨项目身份拒绝'],
  ['attempt2-A-three-valid', '三插件正向验证 · Java 项目'],
  ['attempt2-H-gitleaks-fail', 'Gitleaks · 受控泄漏负例'],
  ['attempt2-G-semgrep-fail', 'Semgrep · 受控规则负例'],
  ['attempt2-F-cosign-tampered', 'Cosign · 篡改负例'],
  ['attempt2-B-cosign-disabled', 'Cosign · 显式禁用'],
  ['attempt2-E-all-disabled', '全部插件 · 显式禁用'],
  ['attempt2-I-cosign-timeout', 'Cosign · 受控超时'],
  ['attempt2-O-cosign-unavailable', 'Cosign · 工具不可用'],
];
const sha = b => createHash('sha256').update(b).digest('hex');
const id = x => typeof x === 'string' && /^[-a-zA-Z0-9_.:/]+$/.test(x) && x.length < 300 ? x : null;
const hash = x => /^[a-f0-9]{64}$/.test(x ?? '') ? x : null;
const iso = x => typeof x === 'string' && /^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(x) ? x : null;
const status = (x, allowed) => allowed.includes(x) ? x : 'UNAVAILABLE';
function read(relative) {
  const full = path.join(root, relative);
  if (fs.realpathSync(full) !== full) throw Error('SOURCE_SYMLINK_REJECTED');
  const st = fs.statSync(full);
  if (!st.isFile() || st.size > 4 * 1024 * 1024) throw Error('SOURCE_TYPE_OR_SIZE');
  const bytes = fs.readFileSync(full);
  return {value: JSON.parse(bytes), sha256: sha(bytes), path: relative};
}
function run([runId, label]) {
  const relative = runs + runId + '/';
  try {
    const summary = read(relative + 'candidate-summary.json');
    const seal = read(relative + 'candidate-seal.json');
    if (seal.value.files?.['candidate-summary.json']?.sha256 !== summary.sha256) throw Error('SUMMARY_SEAL_MISMATCH');
    const s = summary.value;
    if (s.runId !== runId || s.productionEvidence !== false || s.kind !== 'SecuritySummaryCandidate') throw Error('SOURCE_IDENTITY_MISMATCH');
    const config=read(relative+'effective-config.json');
    if(seal.value.files?.['effective-config.json']?.sha256!==config.sha256 || config.value.effectiveConfigDigest!==s.effectiveConfigDigest)throw Error('CONFIG_SEAL_MISMATCH');
    const plugins = ['gitleaks', 'semgrep', 'cosign'].map(pluginId => {
      try {
        const saved = read(relative + pluginId + '.result.json');
        if (seal.value.files?.[pluginId + '.result.json']?.sha256 !== saved.sha256) throw Error('RESULT_SEAL_MISMATCH');
        const p = saved.value;
        verifyResult(p);
        if (p.runId !== runId || p.pluginId !== pluginId || p.resultDigest !== s.pluginResults?.find(v => v.pluginId === pluginId)?.resultDigest) throw Error('RESULT_BINDING_MISMATCH');
        if (p.rawReportDigest) {
          const raw = read(relative + pluginId + '.raw.json');
          if (raw.sha256 !== p.rawReportDigest || seal.value.files?.[pluginId + '.raw.json']?.sha256 !== raw.sha256) throw Error('RAW_REPORT_HASH_MISMATCH');
        }
        const real = p.evidenceRefs.some(e => e.kind === 'REAL_CONTROLLED_EXECUTION' && e.validationRunId === runId);
        const executionStatus = status(p.executionStatus, ['COMPLETED','DISABLED','SKIPPED','NOT_CONFIGURED','UNSUPPORTED','POLICY_ERROR','ERROR']);
        return {pluginId, availability: 'AVAILABLE', executionStatus,
          enabled: executionStatus === 'DISABLED' ? false : true,
          policyDecision: p.policyDecision === null ? null : status(p.policyDecision, ['PASS','WARN','FAIL']),
          oldGateDecision: p.oldGateDecision == null ? null : status(p.oldGateDecision, ['PASS','WARN','FAIL']),
          evidenceClass: real ? 'REAL' : 'NOT_TESTED', displayMode: 'REPLAY',
          executionScope: id(p.executionScope), startedAt: iso(p.startedAt), completedAt: iso(p.completedAt),
          resultDigest: hash(p.resultDigest), rawReportDigest: hash(p.rawReportDigest), factDigest: hash(p.factDigest),
          failureReason: id(p.failureReason), evaluationCount: p.evaluationCount,
          policy:{policyVersion:id(p.policy?.policyVersion),securityLevel:id(p.policy?.securityLevel),profile:id(p.policy?.profile),
            effectivePolicy:p.policy?.effectivePolicy??null,appliedOverrides:p.policy?.appliedOverrides??[],factDigest:hash(p.factDigest)},
          source: {path: saved.path, sha256: saved.sha256}, integrity: 'HASH_MATCH'};
      } catch (e) { return {pluginId, availability: 'UNAVAILABLE', executionStatus: 'UNAVAILABLE', policyDecision: null, reason: safeError(e)}; }
    });
    return {runId, label, availability: 'AVAILABLE', projectId: id(s.projectId),
      overallDecision: status(s.overallDecision, ['PASS','WARN','FAIL','ERROR','POLICY_ERROR','DISABLED','BLOCKED']),
      globalMode: id(s.globalMode), securityLevel: id(s.securityLevel), policyVersion: id(s.policyVersion), profile: id(s.profile),
      source: {path: summary.path, sha256: summary.sha256}, sealSha256: seal.sha256,
      plugins,configuration:{enabled:config.value.enabled,globalMode:id(config.value.globalMode),securityLevel:id(config.value.securityLevel),profile:id(config.value.profile),
        policyVersion:id(config.value.policyVersion),effectiveConfigDigest:hash(config.value.effectiveConfigDigest),
        plugins:Object.fromEntries(Object.entries(config.value.plugins??{}).filter(([key])=>realThreePluginsRegistry().ids().includes(key)).map(([key,value])=>[key,{enabled:typeof value.enabled==='boolean'?value.enabled:null}])),
        source:{path:config.path,sha256:config.sha256}},
      artifact:{summary:{path:summary.path,sha256:summary.sha256},seal:{path:seal.path,sha256:seal.sha256},fileCount:Object.keys(seal.value.files??{}).length,
        statuses:Object.fromEntries((s.pluginResults??[]).map(p=>[p.pluginId,{executionStatus:status(p.executionStatus,['COMPLETED','DISABLED','SKIPPED','NOT_CONFIGURED','UNSUPPORTED','POLICY_ERROR','ERROR']),policyDecision:p.policyDecision==null?null:status(p.policyDecision,['PASS','WARN','FAIL'])}]))},
      completedAt: plugins.map(p => p.completedAt).filter(Boolean).sort().at(-1) ?? null};
  } catch (e) { return {runId, label, availability: 'UNAVAILABLE', reason: safeError(e), plugins: ['gitleaks','semgrep','cosign'].map(pluginId => ({pluginId, availability:'UNAVAILABLE', policyDecision:null, reason:safeError(e)}))}; }
}
function safeError(e) {
  return /^[A-Z_]+$/.test(e.message) ? e.message : 'SOURCE_MISSING_OR_INVALID';
}
function consumer(relative, kind) {
  try {
    const src = read(evidence + relative), v = src.value;
    const receipt = kind === 'Loki' ? v.output?.lokiDelivery : v.output?.httpDelivery;
    if (!receipt || receipt.productionDelivery !== false) throw Error('NON_CANDIDATE_RECEIPT');
    return {name: kind, availability: 'AVAILABLE', evidenceClass:'MOCK', displayMode:'REPLAY',
      classification: id(v.classification), runId: id(receipt.runId),
      deliveryState: id(receipt.deliveryState), realRemoteDelivery: id(receipt.realRemoteDelivery),
      timestamp: iso(receipt.timestamp) ?? iso(v.journal?.at(-1)?.timestamp),
      httpStatus: Number.isInteger(receipt.httpStatus) ? receipt.httpStatus : null,
      httpRequestCount: receipt.httpRequestCount, receiptDigest: hash(receipt.receiptDigest),
      resultDigests: Object.fromEntries((v.sourceResults ?? []).filter(p => ['gitleaks','semgrep','cosign'].includes(p.pluginId)).map(p => [p.pluginId,hash(p.resultDigest)])),
      routerState: id(v.output.deliveryStatus), productionDeliveryCount: v.output.productionDeliveryCount,
      source: {path: src.path, sha256:src.sha256}};
  } catch(e) { return {name:kind,availability:'UNAVAILABLE',reason:safeError(e)}; }
}
export function overview() {
  let baseline;
  try { const s=read(evidence+'security-manager-v2-loki/verdict.json');
    const keys=['PRODUCTION_SECURITY_MANAGER','FINAL_WIRED_CAPABILITY','ORIGINAL_EVIDENCE_INTEGRITY','TRIVY_RUNTIME_FACT_CAPTURE','DEFECTDOJO_RUNTIME_FACT_CAPTURE','JENKINS_REAL_CI','GRAFANA_REAL_QUERY','SUMMARY_V2_MIGRATION'];
    baseline={...Object.fromEntries(keys.map(k=>[k,id(s.value.verdict[k])??'UNAVAILABLE'])), source:{path:s.path,sha256:s.sha256}}; }
  catch(e) { baseline={unavailable:true,reason:safeError(e)}; }
  let dojo;
  try { const s=read(evidence+'security-manager-v2-dojo-http/verdict.json'); dojo={httpAdapter:s.value.verdict.DEFECTDOJO_HTTP_ADAPTER,realDelivery:s.value.verdict.DEFECTDOJO_REAL_REMOTE_DELIVERY,source:{path:s.path,sha256:s.sha256}}; }
  catch(e) { dojo={httpAdapter:'UNAVAILABLE',realDelivery:'UNAVAILABLE',reason:safeError(e)}; }
  let dojoReal;
  try{let src;try{try{src=read('evidence/2026-11-06/dojo-real-execution/delivered-state.json');}catch(e){if(e.code!=='ENOENT')throw e;src=read('evidence/2026-11-06/dojo-real-execution/state.json');}}catch(e){if(e.code!=='ENOENT')throw e;src=read('evidence/2026-11-06/dojo-real-delivery/state.json');}const {receiptDigest,...v}=src.value;
    if(digest(v)!==receiptDigest||v.kind!=='DefectDojoRealDeliveryState'||!['BLOCKED','DELIVERED'].includes(v.state)||!id(v.runId)||!hash(v.resultDigest)||v.productionGovernanceMutations!==0)throw Error('DOJO_REAL_STATE_INVALID');
    if(v.state==='DELIVERED'&&(v.queryState!=='VERIFIED'||v.productId!==7||v.engagementId!==4||v.findingIds?.length!==2||v.findingUrls?.some((url,i)=>url!=='http://defectdojo.devops.local/finding/'+v.findingIds[i])))throw Error('DOJO_REAL_BINDING_INVALID');
    dojoReal={...v,source:{path:src.path,sha256:src.sha256}};
  }catch(e){dojoReal={state:'NOT_TESTED',reason:safeError(e)};}
  let supplyChain;
  try{const src=read('evidence/2026-11-06/supply-chain-view/snapshot.json');const {receiptDigest,...v}=src.value;
    if(digest(v)!==receiptDigest||v.kind!=='SupplyChainSecuritySnapshot'||v.candidateDigest!=='sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55'||v.release!==0||v.rollout!==0||v.sbom.candidateDigestBinding!=='UNVERIFIED')throw Error('SUPPLY_CHAIN_RECEIPT_INVALID');
    supplyChain={...v,source:{path:src.path,sha256:src.sha256}};
  }catch(e){supplyChain={availability:'UNAVAILABLE',reason:safeError(e)};}
  let registryView,grafana,ciCd,semgrepAdmission;
  try{const src=readCode('infra/security/manager-v2/registry.mjs');registryView={kind:'EXISTING_CODE_OWNED_REGISTRY',classification:'CANDIDATE',source:src,
    entries:realThreePluginsRegistry().all().map(p=>({pluginId:p.pluginId,pluginVersion:p.pluginVersion,runner:p.runner,executionMode:p.executionMode,defaultEnabled:p.enabled,requiredCapabilities:p.requiredCapabilities,supportedProfiles:p.supportedProfiles,timeoutMs:p.timeout}))};}
  catch(e){registryView={availability:'UNAVAILABLE',reason:safeError(e),entries:[]};}
  try{const src=read('infra/security/manager-v2/observability/dashboard.json');grafana={classification:'CANDIDATE',uid:id(src.value.uid),title:String(src.value.title),panelCount:src.value.panels.length,
    panelTitles:src.value.panels.map(p=>String(p.title)),realQuery:baseline.GRAFANA_REAL_QUERY??'UNAVAILABLE',productionActivation:baseline.PRODUCTION_SECURITY_MANAGER??'UNAVAILABLE',importState:'UNVERIFIED',download:'/candidate-dashboard.json',source:{path:src.path,sha256:src.sha256}};}
  catch(e){grafana={availability:'UNAVAILABLE',reason:safeError(e)};}
  try{const src=read('evidence/2026-11-06/grafana-v2-real/view-receipt.json');const {receiptDigest,...v}=src.value;
    if(digest(v)!==receiptDigest||v.kind!=='GrafanaRealQueryReceipt'||v.dashboardUid!=='security-manager-v2-candidate'||
      v.dashboardUrl!=='http://grafana.devops.local/d/security-manager-v2-candidate/devsecops-security-manager-v2-overview'||
      v.dashboardApiStatus!==200||v.grafanaQueryApiStatus!==200||v.matchingRunObserved!==true||!hash(v.resultDigest)||!id(v.runId))throw Error('GRAFANA_QUERY_RECEIPT_INVALID');
    grafana={...grafana,classification:'HISTORICAL / REAL_QUERY',uid:v.dashboardUid,url:v.dashboardUrl,folderUid:id(v.folderUid),
      importState:'VERIFIED',realQuery:'VERIFIED',runId:v.runId,resultDigest:v.resultDigest,verifiedAt:iso(new Date(v.verifiedAt).toISOString()),executionTime:iso(v.executionTime),
      sourceClassification:id(v.sourceClassification),dataPanelCount:v.dataPanelCount,queryPanelCount:v.queryPanelCount,panelResults:v.panelResults,
      productionActivation:'NOT_ACTIVE',querySource:{path:src.path,sha256:src.sha256}};
  }catch(e){if(e.code!=='ENOENT')grafana={...grafana,realQuery:'UNAVAILABLE',queryReason:safeError(e)};}
  try{const src=read('evidence/2026-11-06/ci-cd-real/attempt2/result.json');const v=src.value,{receiptDigest,...body}=v;
    if(digest(body)!==receiptDigest||v.status!=='SUCCESS'||!v.updated?.verified||!v.restored?.verified||v.policyDecision!=='PASS')throw Error('CI_CD_RECEIPT_INVALID');
    ciCd={classification:'HISTORICAL',evidenceClass:'REAL',build:v.build,runId:id(v.runId),triggerCommit:id(v.triggerCommit),policyDecision:v.policyDecision,resultDigest:hash(v.resultDigest),completedAt:iso(v.completedAt),
      updateCommit:id(v.update.afterCommit),restoreCommit:id(v.restore.afterCommit),updatedValue:v.updated.value,restoredValue:v.restored.value,
      buildUrl:'http://jenkins.devops.local/job/security-gitlab-push-demo/'+v.build+'/',source:{path:src.path,sha256:src.sha256}};}
  catch(e){ciCd={availability:'UNAVAILABLE',reason:safeError(e)};}
  try{const src=read('evidence/2026-11-06/view-candidate-integration/state.json');semgrepAdmission={...src.value.semgrep,observedAt:src.value.observedAt,classification:'HISTORICAL',source:{path:src.path,sha256:src.sha256}};}
  catch(e){semgrepAdmission={availability:'UNAVAILABLE',reason:safeError(e)};}
  return {kind:'SecurityManagerReadOnlyView', servedAt:new Date().toISOString(),registry:registryView,grafana,ciCd,semgrepAdmission,dojoReal,supplyChain,
    mode:'REPLAY', liveScan:false, baseline, dojo, runs:catalog.map(run),
    consumers:[consumer('security-manager-v2-loki/loki-protocol-samples-attempt5/A-three-valid.json','Loki'),
      consumer('security-manager-v2-dojo-http/samples-attempt5/gitleaks-success.json','DefectDojo')],
    notices:['已有受控真实执行记录的只读展示；当前没有扫描任务。','Consumer 使用独立历史 Run ID，不能与所选插件记录拼为同轮运行。','当前文件哈希匹配不等于恢复历史证据完整性。']};
}
function readCode(relative){const full=path.join(root,relative);if(fs.realpathSync(full)!==full)throw Error('SOURCE_SYMLINK_REJECTED');return {path:relative,sha256:sha(fs.readFileSync(full))};}
