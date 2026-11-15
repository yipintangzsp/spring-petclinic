import {cmdResult,fileValue} from './recorder.mjs';

// Runtime collector for the cosign source (signing.mjs, stages bootstrap /
// release / admission). Mirrors the frozen shape policy/cosign-parent.mjs
// replays through policy/cosign-observations.mjs: stage, configuration,
// curated environment, runtime (tool manifest + lease + per-tool hashes),
// file contents, indexed command results, IO outcomes, registry responses
// and admission dry-run results. The sops decrypt command result contains
// the signing bundle (private key + password) and the Harbor password is
// never recorded at all — this object lives only in the signing process
// memory; the emitted receipt carries digests only.
export function createCosignCollector(stage) {
  const raw = {stage,configuration:{mode:stage},environment:{},runtime:{tools:{}},files:{},commands:{},io:{},registry:[],admissions:[]};
  return {raw,
    environment() {
      raw.environment = {BUILD_NUMBER:process.env.BUILD_NUMBER,HARBOR_USER:process.env.HARBOR_USER,
        ...(process.env.HEAVY_HOLDER ? {HEAVY_HOLDER:process.env.HEAVY_HOLDER} : {}),
        SIGNING_AGE_FILE:process.env.SIGNING_AGE_FILE ? true : undefined,
        HARBOR_PASS:process.env.HARBOR_PASS ? true : undefined};
    },
    runtimeManifest(text,expectedSha256) { raw.runtime.manifest = text; raw.runtime.expectedManifestSha256 = expectedSha256; },
    runtimeLease(r) { raw.runtime.lease = cmdResult(r); },
    tool(p,entry) { raw.runtime.tools[p] = entry; },
    file(p,text) { raw.files[p] = fileValue(text); },
    cmd(tool,args,r) { const key = tool+':'+args[0]; (raw.commands[key] ??= []).push(cmdResult(r)); },
    io(name,value) { raw.io[name] = {value}; },
    ioError(name,e) { raw.io[name] = {error:String(e?.message ?? e)}; },
    registry(record) { raw.registry.push(record); },
    admission(r) { raw.admissions.push(cmdResult(r)); },
    currentImage(r) { raw.currentImage = cmdResult(r); }
  };
}
