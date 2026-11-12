// Allowlisted collector for the Falco V2 candidate runner (G-F2).
// Collection no longer runs as the devops operator through sudo kubectl:
// the collector's only operation is one SSH call to the dedicated
// restricted entry security-falco@127.0.0.1 (uid/gid 1007, authorized_keys
// restrict + forced command "collect-v1" + setpriv --no-new-privs). The
// entry executes a fixed kubectl operation set (sensor pod listing,
// DaemonSet, node, workload pod listing, three Falco log slices, healthz)
// with a dedicated least-privilege ServiceAccount kubeconfig
// (security-falco-collector in devsecops-system: pods get/list and
// pods/log get and daemonsets/platform-falco get in devsecops-system,
// pods get/list in petclinic, nodes/devops get) and returns one JSON
// packet, which this module validates field by field before any of it
// reaches the frozen Policy adapter. No Falco configuration, rule, or
// production workload is ever modified by this module.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import os from 'node:os';
import path from 'node:path';
const exec = promisify(execFile);
const MAX = 16 * 1024 * 1024;
const ENTRY_HOST = '127.0.0.1';
function result(v) {
  if (!v || v.status !== 0 || typeof v.stdout !== 'string') throw Error('RUNNER_ERROR');
  return {status: 0, stdout: v.stdout};
}
export function falcoCollectorPacket(packet, project, windowEndMs) {
  if (!packet || packet.kind !== 'FalcoCollectorPacket') throw Error('RUNNER_ERROR');
  if (packet.projectId !== project?.collectorProjectId) throw Error('RUNNER_ERROR');
  if (packet.windowEndMs !== windowEndMs) throw Error('RUNNER_ERROR');
  const idn = packet.identity ?? {};
  if (idn.user !== project.collectorEntryUser || idn.uid !== project.collectorUid ||
      idn.gid !== project.collectorGid ||
      idn.serviceAccount !== project.collectorServiceAccount ||
      idn.serviceAccountNamespace !== project.collectorServiceAccountNamespace) throw Error('RUNNER_ERROR');
  if (!packet.health || typeof packet.health.ok !== 'boolean') throw Error('RUNNER_ERROR');
  const r = packet.results ?? {};
  const out = {
    ds: result(r.ds), sensorPods: result(r.sensorPods), node: result(r.node),
    workloads: result(r.workloads), diagnosticLog: result(r.diagnosticLog),
    sampleLog: result(r.sampleLog), fullLogText: result(r.fullLog).stdout,
    health: packet.health, identity: idn,
  };
  let pod;
  try {
    const items = JSON.parse(out.sensorPods.stdout).items.filter(p => !p.metadata.deletionTimestamp);
    if (items.length !== 1) throw Error('RUNNER_ERROR');
    pod = items[0];
  } catch (e) { if (e.message === 'RUNNER_ERROR') throw e; throw Error('RUNNER_ERROR'); }
  const podName = pod.metadata.name, podIP = pod.status?.podIP;
  if (!/^[a-z0-9][a-z0-9-]{0,60}$/.test(podName) || !/^\d+\.\d+\.\d+\.\d+$/.test(podIP ?? '')) throw Error('RUNNER_ERROR');
  return {...out, sensorPod: pod};
}
export async function collectFalco(project, {windowEndMs, signal, projectId} = {}) {
  if (project.collectorEntryUser !== 'security-falco' || project.collectorEntryHost !== ENTRY_HOST ||
      project.collectorUid !== 1007 || project.collectorGid !== 1007 ||
      project.collectorProjectId !== projectId) throw Error('RUNNER_ERROR');
  const key = path.join(os.homedir(), '.ssh', 'security-manager-v2-falco');
  const args = ['-F', '/dev/null', '-T', '-n', '-i', key,
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'HostKeyAlias=127.0.0.1',
    '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=5',
    project.collectorEntryUser + '@' + ENTRY_HOST, 'collect-v1 ' + projectId + ' ' + windowEndMs];
  let stdout;
  try {
    ({stdout} = await exec('/usr/bin/ssh', args, {
      timeout: 25000, maxBuffer: MAX, signal,
      env: {PATH: '/usr/bin:/bin', LANG: 'C'},
    }));
  } catch (e) {
    if (e?.code === 'ABORT_ERR' || signal?.aborted) throw Error('RUNNER_CANCELLED');
    throw Error('RUNNER_ERROR');
  }
  let packet;
  try { packet = JSON.parse(stdout); } catch { throw Error('RUNNER_ERROR'); }
  return falcoCollectorPacket(packet, project, windowEndMs);
}
