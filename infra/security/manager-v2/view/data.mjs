// Read-only, allowlisted projection. No scanner, policy evaluation or consumer execution.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {verifyResult} from '../result.mjs';
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
          source: {path: saved.path, sha256: saved.sha256}, integrity: 'HASH_MATCH'};
      } catch (e) { return {pluginId, availability: 'UNAVAILABLE', executionStatus: 'UNAVAILABLE', policyDecision: null, reason: safeError(e)}; }
    });
    return {runId, label, availability: 'AVAILABLE', projectId: id(s.projectId),
      overallDecision: status(s.overallDecision, ['PASS','WARN','FAIL','ERROR','POLICY_ERROR','DISABLED','BLOCKED']),
      globalMode: id(s.globalMode), securityLevel: id(s.securityLevel), policyVersion: id(s.policyVersion), profile: id(s.profile),
      source: {path: summary.path, sha256: summary.sha256}, sealSha256: seal.sha256,
      plugins, completedAt: plugins.map(p => p.completedAt).filter(Boolean).sort().at(-1) ?? null};
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
  return {kind:'SecurityManagerReadOnlyView', servedAt:new Date().toISOString(),
    mode:'REPLAY', liveScan:false, baseline, dojo, runs:catalog.map(run),
    consumers:[consumer('security-manager-v2-loki/loki-protocol-samples-attempt5/A-three-valid.json','Loki'),
      consumer('security-manager-v2-dojo-http/samples-attempt5/gitleaks-success.json','DefectDojo')],
    notices:['已有受控真实执行记录的只读展示；当前没有扫描任务。','Consumer 使用独立历史 Run ID，不能与所选插件记录拼为同轮运行。','当前文件哈希匹配不等于恢复历史证据完整性。']};
}
