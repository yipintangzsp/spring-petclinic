// Allowlisted collector for the Falco V2 candidate runner.
// No shell, no configurable commands: every operation is a fixed argv array
// against the pinned sensor / namespaces from falco/projects.json, executed
// through the operator's pre-existing passwordless sudo on devops (the same
// authority the V1 runtime health gate used). No Falco configuration, rule,
// or production workload is ever modified by this module.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec = promisify(execFile);
const MAX = 4 * 1024 * 1024;
async function kubectl(args, signal) {
  try {
    const {stdout} = await exec('/usr/bin/sudo', ['-n', 'kubectl', '--request-timeout=15s', ...args], {
      timeout: 20000, maxBuffer: MAX, signal,
      env: {PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C'},
    });
    return {status: 0, stdout};
  } catch (e) {
    if (e?.code === 'ABORT_ERR' || signal?.aborted) throw Error('RUNNER_CANCELLED');
    throw Error('RUNNER_ERROR');
  }
}
const iso = ms => new Date(ms).toISOString();
export async function collectFalco(project, {windowEndMs, signal} = {}) {
  const ns = project.sensorNamespace, label = project.sensorPodLabel;
  // Sensor pod name is needed for the logs operations; resolve it first from
  // the same listing that is later handed to the frozen Policy adapter.
  const sensorPods = await kubectl(['-n', ns, 'get', 'pods', '-l', label, '-o', 'json'], signal);
  let pod;
  try {
    const items = JSON.parse(sensorPods.stdout).items.filter(p => !p.metadata.deletionTimestamp);
    if (items.length !== 1) throw Error('RUNNER_ERROR');
    pod = items[0];
  } catch (e) { if (e.message === 'RUNNER_ERROR') throw e; throw Error('RUNNER_ERROR'); }
  const podName = pod.metadata.name, podIP = pod.status?.podIP;
  if (!/^[a-z0-9][a-z0-9-]{0,60}$/.test(podName) || !/^\d+\.\d+\.\d+\.\d+$/.test(podIP ?? '')) throw Error('RUNNER_ERROR');
  const windowStartMs = windowEndMs - 15000;
  const fullSinceMs = windowEndMs - 180000;
  const [ds, node, workloads, diagnosticLog, sampleLog, fullLog] = await Promise.all([
    kubectl(['-n', ns, 'get', 'ds', project.sensorDaemonSet, '-o', 'json'], signal),
    kubectl(['get', 'node', project.node, '-o', 'json'], signal),
    kubectl(['-n', project.workloadNamespace, 'get', 'pods', '-o', 'json'], signal),
    kubectl(['-n', ns, 'logs', podName, '-c', 'falco', '--tail=500'], signal),
    kubectl(['-n', ns, 'logs', podName, '-c', 'falco', '--since-time=' + iso(windowStartMs), '--tail=1000'], signal),
    kubectl(['-n', ns, 'logs', podName, '-c', 'falco', '--since-time=' + iso(fullSinceMs), '--tail=1000'], signal),
  ]);
  let health;
  try {
    const r = await fetch('http://' + podIP + ':8765/healthz', {signal: AbortSignal.timeout(5000)});
    health = r.ok ? {ok: true, status: r.status} : {ok: false, error: 'HTTP_' + r.status};
  } catch { health = {ok: false, error: 'HEALTHZ_UNREACHABLE'}; }
  return {ds, sensorPods, node, workloads, diagnosticLog, sampleLog, fullLogText: fullLog.stdout, health, sensorPod: pod};
}
