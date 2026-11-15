import {cmdResult,fileValue,fileError} from './recorder.mjs';

// Runtime collector for the falco-baseline / falco-final sources
// (runtime/health.mjs, mode baseline|check). Mirrors the frozen shape
// policy/falco-parent.mjs replays, including the raw time/sample binding:
// each live sample records the exact window-end clock captured BEFORE its
// log query, the raw log result and the raw workload inventory result.
// One collector instance serves one invocation; the stage (mode) selects
// the canonical source id at emission time.
export function createFalcoCollector(mode) {
  const raw = {mode,build:String(process.env.BUILD_NUMBER ?? ''),now:Date.now(),configuration:{},
    observations:{files:{},samples:[]}};
  return {raw,
    leaseOk() { raw.observations.leaseOwned = true; },
    file(name,text) { raw.observations.files[name] = fileValue(text); },
    fileErr(name,e) { raw.observations.files[name] = fileError(e); },
    cmd(name,r) { raw.observations[name] = cmdResult(r); },
    sample(windowEndMs,logResult,workloadsResult) {
      raw.observations.samples.push({windowEndMs,log:cmdResult(logResult),workloads:cmdResult(workloadsResult)});
    },
    health(status) { raw.observations.health = {ok:true,status}; },
    healthError(e) { if (!raw.observations.health) raw.observations.health = {error:String(e?.message ?? e)}; },
    flag(name,ok) { raw.observations[name] = ok; }
  };
}
export const falcoSourceId = mode => mode === 'baseline' ? 'falco-baseline' : 'falco-final';
