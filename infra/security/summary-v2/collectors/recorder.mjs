// Passive observation primitives for the Summary V2 runtime collectors
// (T08a / C1). A collector only ever READS values the production flow already
// produced: original arguments, exit codes, stdout/stderr and file contents
// are recorded verbatim, in memory. Recording must never throw into the
// observed flow, so every hook routes through guard().

// Normalize a spawnSync-style result into the frozen command shape the Policy
// adapters replay: {status, stdout, stderr, error?}.
export function cmdResult(r) {
  const out = {status: r?.status ?? null, stdout: r?.stdout == null ? '' : String(r.stdout), stderr: r?.stderr == null ? '' : String(r.stderr)};
  if (r?.error) out.error = String(r.error.message ?? r.error);
  return out;
}
// Frozen file-read shape: {value} on success, {error} on failure.
export const fileValue = value => ({value: typeof value === 'string' ? value : String(value)});
export const fileError = e => ({error: String(e?.message ?? e)});
// Run a recording step; swallow any recorder-side failure so the production
// module's arguments, exit code and IO are never affected by collection.
export function guard(fn) { try { return fn(); } catch { return undefined; } }
