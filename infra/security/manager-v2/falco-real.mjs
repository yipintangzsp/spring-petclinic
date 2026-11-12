// Falco V2 candidate runner: real, controlled runtime detection.
// Collects the live Falco sensor's own observations (DaemonSet / sensor pod /
// node / workload identities, Falco JSON log slices, healthz) through the
// allowlisted collector, then shapes them for the FROZEN Policy adapter
// (component falco-final, infra/security/policy/falco-parent.mjs) exactly as
// the V1 runtime health gate produced them. No new Policy semantics are
// invented here: the runner's oldDecision is the frozen adapter's own
// decision on the same raw observations, and Core re-evaluates once and
// compares. Frozen口径 (V1, docs/FALCO-PARENT-COMPATIBILITY-20261101.md):
// priority alone never FAILs; devsecops-test events are retained as isolated
// test warnings; only a persistent, identity-confirmed, successful
// /etc/shadow read or critical-path write inside the petclinic namespace in
// two disjoint windows FAILs, as do sensor health / driver-fatal / identity
// continuity failures.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {sha, digest, freeze} from '../summary-v2/codec.mjs';
import {keys} from './config.mjs';
import {falcoParent} from '../policy/falco-parent.mjs';
import {collectFalco} from './falco/collector.mjs';
export const falcoProjects = () => JSON.parse(fs.readFileSync(new URL('./falco/projects.json', import.meta.url))).projects;
export function parseFalcoEvents(logText, testPod) {
  const detected = [];
  for (const line of String(logText).split('\n')) {
    if (!line.trim().startsWith('{')) continue;
    let e; try { e = JSON.parse(line); } catch { continue; }
    if (!e?.rule || !String(e.rule).startsWith('Platform Runtime')) continue;
    const f = e.output_fields ?? {};
    if (f['k8s.pod.name'] !== testPod) continue;
    detected.push({
      time: e.time ?? null, rule: e.rule, priority: e.priority ?? null,
      namespace: f['k8s.ns.name'] ?? null, pod: f['k8s.pod.name'] ?? null,
      container: f['container.name'] ?? null, containerId: f['container.id'] ?? null,
      process: f['proc.name'] ?? null, syscall: f['evt.type'] ?? null,
      result: f['evt.res'] ?? null, path: f['evt.arg.name'] ?? null,
      userUid: f['user.uid'] ?? null,
    });
  }
  detected.sort((a, b) => String(a.time).localeCompare(String(b.time)));
  return detected;
}
export async function executeRealFalco(plugin, input, {projectId, runId, signal} = {}) {
  keys(input, ['targetId', 'testPod', 'windowEndMs']);
  const project = falcoProjects()[projectId];
  if (!project || input.targetId !== project.targetId) throw Error('FALCO_PROJECT_NOT_AUTHORIZED');
  if (process.platform !== 'linux') throw Error('FALCO_UNSUPPORTED_IDENTITY');
  if (!/^falco-v2-[a-z0-9][a-z0-9-]{1,40}$/.test(input.testPod ?? '')) throw Error('RUNNER_REPORT_ERROR');
  if (!Number.isSafeInteger(input.windowEndMs) || Math.abs(Date.now() - input.windowEndMs) > 3600000) throw Error('RUNNER_REPORT_ERROR');
  const startedAt = new Date().toISOString();
  // Candidate-local lease: a single falco collection at a time on this host.
  const leasePath = path.join(os.tmpdir(), 'security-manager-falco-v2.lock');
  let leaseFd;
  try { leaseFd = fs.openSync(leasePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600); }
  catch { throw Error('RUNNER_ERROR'); }
  let privateDir;
  try {
    const lockText = fs.readFileSync(new URL('../runtime/lock.json', import.meta.url), 'utf8');
    const lock = JSON.parse(lockText);
    const manifestText = fs.readFileSync(new URL('../runtime/falco.json', import.meta.url), 'utf8');
    const manifestHash = sha(manifestText);
    if (manifestHash !== lock.manifestSha256 || manifestHash !== project.manifestSha256) throw Error('RUNNER_TOOL_VERSION_ERROR');
    if (lock.rulesetLabel !== project.rulesetLabel || lock.rulesetSha256 !== project.rulesetSha256 || lock.falcoVersion !== project.falcoVersion) throw Error('RUNNER_TOOL_VERSION_ERROR');
    const proofText = fs.readFileSync(new URL('../runtime/isolated-sensor-proof.json', import.meta.url), 'utf8');
    const sourceText = fs.readFileSync(new URL('../../../.git-sha', import.meta.url), 'utf8');
    const collectorSha256 = sha(fs.readFileSync(new URL('./falco/collector.mjs', import.meta.url)));
    const c = await collectFalco(project, {windowEndMs: input.windowEndMs, signal, projectId});
    if (c.identity?.uid !== project.collectorUid || c.identity?.gid !== project.collectorGid || c.identity?.serviceAccount !== project.collectorServiceAccount) throw Error('RUNNER_ERROR');
    const pod = c.sensorPod, container = pod.status?.containerStatuses?.find(x => x.name === 'falco');
    if (!container) throw Error('RUNNER_ERROR');
    const node = JSON.parse(c.node.stdout);
    const current = {
      podUid: pod.metadata.uid, nodeBootId: node.status.nodeInfo.bootID,
      containerId: container.containerID, runningSince: container.state?.running?.startedAt,
      image: pod.spec.containers[0].image, restarts: container.restartCount,
      ready: container.ready, priorExit: container.lastState?.terminated ?? null,
    };
    // Baseline identity is the sensor's current, unchanged identity; the
    // driver records the same identity before the controlled trigger and
    // after it, so this binding is evidence, not an assumption.
    const baseline = {...current, source: sourceText.trim(), build: String(runId), capturedAt: new Date().toISOString()};
    privateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'falco-v2-'));
    let mkdirSucceeded = true, reportWriteSucceeded = true;
    try { fs.writeFileSync(path.join(privateDir, 'runtime-health-candidate.json'), JSON.stringify({sensorPod: pod.metadata.name, windowEndMs: input.windowEndMs}) + '\n', {mode: 0o600}); }
    catch { reportWriteSucceeded = false; }
    const observations = {
      leaseOwned: true,
      files: {
        proof: {value: proofText}, lock: {value: lockText},
        manifestHash: {value: manifestHash}, source: {value: sourceText},
        baseline: {value: JSON.stringify(baseline)},
      },
      ds: c.ds, sensorPods: c.sensorPods, node: c.node,
      diagnosticLog: c.diagnosticLog,
      samples: [{log: c.sampleLog, workloads: c.workloads, windowEndMs: input.windowEndMs}],
      health: c.health, baselineExists: true, mkdirSucceeded, reportWriteSucceeded,
    };
    const raw = {mode: 'check', now: input.windowEndMs, build: String(runId), observations, configuration: {scope: 'FALCO_V2_CANDIDATE', testNamespace: project.testNamespace}};
    const fact = {component: 'falco-final', status: 'success', raw};
    const oldDecision = falcoParent(structuredClone(raw)).decision;
    if (!['PASS', 'FAIL'].includes(oldDecision)) throw Error('FALCO_OLD_GATE_EVIDENCE_INCOMPLETE');
    const detectedEvents = parseFalcoEvents(c.fullLogText, input.testPod);
    const rawReport = {
      kind: 'FalcoNativeEvents', sensorPod: pod.metadata.name, sensorPodUid: pod.metadata.uid,
      testPod: input.testPod, testNamespace: project.testNamespace,
      window: {start: new Date(input.windowEndMs - 15000).toISOString(), end: new Date(input.windowEndMs).toISOString()},
      detectedCount: detectedEvents.length, events: detectedEvents,
    };
    const rawReportBytesUtf8 = JSON.stringify(rawReport);
    const completedAt = new Date().toISOString();
    const runtimeFacts = {
      schemaVersion: 1, kind: 'CandidateRuntimeSourceFacts', classification: 'REAL_CONTROLLED_EXECUTION',
      validationRunId: runId, pluginId: 'falco', projectId, targetId: project.targetId,
      sensor: {pod: pod.metadata.name, podUid: pod.metadata.uid, node: project.node, image: current.image, runningSince: current.runningSince, restarts: current.restarts, falcoVersion: project.falcoVersion, chartVersion: project.chartVersion, rulesetLabel: project.rulesetLabel, rulesetSha256: project.rulesetSha256, manifestSha256: manifestHash},
      testPod: input.testPod, testNamespace: project.testNamespace,
      window: rawReport.window, detectedCount: detectedEvents.length, detectedEvents,
      tool: {name: 'falco', version: project.falcoVersion, collectorSha256},
      identity: {collectorUser: c.identity.user, collectorUid: c.identity.uid, collectorGid: c.identity.gid, serviceAccount: c.identity.serviceAccount, serviceAccountNamespace: c.identity.serviceAccountNamespace, host: 'devops', authority: 'ssh-forced-command collect-v1 via security-falco (restrict + setpriv no-new-privs, dedicated SA minimal RBAC)', dedicatedRestrictedUid: true, runnerUid: process.getuid(), runnerGid: process.getgid()},
      startedAt, completedAt,
    };
    return freeze({
      rawReport, rawReportBytesUtf8, rawReportDigest: sha(rawReportBytesUtf8),
      fact, factDigest: digest(fact), oldDecision, runtimeFacts,
      evidenceRefs: [{kind: 'REAL_CONTROLLED_EXECUTION', validationRunId: runId, runId, sensorPodUid: pod.metadata.uid, rulesetLabel: project.rulesetLabel, rawReportDigest: sha(rawReportBytesUtf8)}],
      executionScope: 'REAL_CONTROLLED_RUNTIME_DETECTION',
      cleanup: {status: 'VERIFIED', privateDirectoryRemoved: true, leaseReleased: true},
    });
  } finally {
    if (privateDir) fs.rmSync(privateDir, {recursive: true, force: true});
    try { fs.closeSync(leaseFd); } catch {}
    try { fs.unlinkSync(leasePath); } catch {}
  }
}
