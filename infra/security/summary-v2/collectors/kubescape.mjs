import {cmdResult,fileValue} from './recorder.mjs';

// Runtime collector for the kubescape source (governance/kubescape.mjs).
// Mirrors the frozen shape policy/kubescape-parent.mjs replays: lock + holder
// identity, per-file hashes, the lease/context/ca/token command results, the
// least-privilege probes, four scan executions with their native reports and
// hashes, and the cleanup / final-report outcomes. The short-lived read-only
// token exists only in this in-memory object; the emitted receipt carries
// digests only.
export function createKubescapeCollector() {
  const raw = {observations:{hashes:{},scans:[]}};
  return {raw,
    lock(lock,holder) { raw.lock = lock; raw.holder = holder; },
    flag(name,ok) { raw.observations[name] = ok; },
    hash(p,value) { raw.observations.hashes[p] = fileValue(value); },
    hashError(p,e) { raw.observations.hashes[p] = {error:String(e?.message ?? e)}; },
    cmd(name,r) { raw.observations[name] = cmdResult(r); },
    scan(index,entry) { raw.observations.scans[index] = entry; },
    scanEntry(r,logWriteSucceeded,reportText,reportSha) {
      return {command:cmdResult(r),logWriteSucceeded,report:fileValue(reportText),hash:fileValue(reportSha)};
    }
  };
}
