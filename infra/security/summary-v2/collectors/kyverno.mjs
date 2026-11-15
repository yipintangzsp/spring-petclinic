import fs from 'node:fs';
import {cmdResult,guard} from './recorder.mjs';
import {readPart,writePart} from '../receipts.mjs';
import {emitReceipt} from './emit.mjs';
import {receiptsDir} from './context.mjs';

// Runtime collectors for the kyverno source, the only two-process source:
// rbac-contract.mjs records the five RBAC command results, admission-gate.mjs
// records configuration, probes, policy, owners and the workload inventory.
// Each process writes its own observation part (cluster state only — no
// credentials); whichever process runs second merges both parts and emits
// the single kyverno receipt, so pipeline order does not matter. A part is
// bound to (source sha, build); parts from another run never merge.

export const runKey = (root = '.') => guard(() => ({
  source: fs.readFileSync(root+'/.git-sha','utf8').trim(),
  build: Number(process.env.BUILD_NUMBER || 0)
}));

export function createRbacPartCollector() {
  const observations = {rbac:[]};
  return {observations,
    cmd(r) { observations.rbac.push(cmdResult(r)); },
    reportWrite(ok) { observations.rbacReportWriteSucceeded = ok; }
  };
}
export function createAdmissionPartCollector() {
  const observations = {probes:[]};
  return {observations,
    reads(configurationReadSucceeded,sourceReadSucceeded) { observations.configurationReadSucceeded = configurationReadSucceeded; observations.sourceReadSucceeded = sourceReadSucceeded; },
    probe(r) { observations.probes.push(cmdResult(r)); },
    policy(r) { observations.policy = cmdResult(r); },
    owner(r) { (observations.owners ??= []).push(cmdResult(r)); },
    workloads(r) { observations.workloads = cmdResult(r); },
    reportWrite(ok) { observations.admissionReportWriteSucceeded = ok; }
  };
}

export function writeKyvernoPart(root,part,run,observations,configuration,outcome) {
  return guard(() => writePart(receiptsDir(root),
    {kind:'SourceObservationPart',source:'kyverno',part,run,observations,outcome,
     ...(configuration !== undefined ? {configuration} : {})}));
}

// Merge both parts and emit the kyverno receipt when both are present for
// the same run. Returns a status object; never throws.
export async function completeKyverno({root = '.',config = {}} = {}) {
  try {
    const dir = receiptsDir(root);
    const rbac = readPart(dir,'kyverno','rbac'), admission = readPart(dir,'kyverno','admission');
    if (!rbac || !admission) return {emitted:false,reason:'kyverno parts incomplete'};
    if (rbac.run?.source !== admission.run?.source || rbac.run?.build !== admission.run?.build)
      return {emitted:false,reason:'kyverno parts from different runs'};
    const raw = {configuration:admission.configuration,
      observations:{...admission.observations,...rbac.observations}};
    const status = rbac.outcome === 'success' && admission.outcome === 'success' ? 'success' : 'error';
    return await emitReceipt('kyverno',{component:'kyverno',status,raw},{root,config});
  } catch (e) {
    return {emitted:false,reason:String(e?.message ?? e)};
  }
}

// The frozen configuration the kyverno adapter replays against: the exact
// files admission-gate.mjs itself reads. Re-read at part-write time; any
// failure marks configurationReadSucceeded false instead of throwing.
export function kyvernoConfiguration(root = '.') {
  const files = {tools:'infra/security/tools-lock.json',baseline:'infra/security/production-baseline.json',
    exceptions:'infra/security/production-exceptions.json',scanner:'infra/security/scanner-tools.json',
    dependencies:'infra/messaging/dependencies.json'};
  const configuration = {}; let ok = true;
  for (const [key,p] of Object.entries(files)) {
    try { configuration[key] = JSON.parse(fs.readFileSync(root+'/'+p,'utf8')); } catch { ok = false; }
  }
  return {configuration,configurationReadSucceeded:ok};
}
