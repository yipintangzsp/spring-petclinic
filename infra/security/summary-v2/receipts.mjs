import fs from 'node:fs';
import path from 'node:path';
import {EXPECTED_SOURCES} from './inventory.mjs';
import {canonical,digest,equal,fail,freeze,object,sha} from './codec.mjs';
import {validateResult} from './results.mjs';

// Cross-process receipt handoff (T08a / C2). The in-process owner in owner.mjs
// claims each source once per owner instance; a real pipeline runs every
// source in its own process, so the once-guarantee and the retry protection
// must live on disk. Layout under the receipts directory:
//   claims/<bindingDigest>/<sourceId>.json  create-only claim, written first
//   results/<bindingDigest>/<sourceId>.json create-only ResolvedPolicyResult
// A claim binds (binding, sourceId) to exactly one resultDigest. A retry that
// reproduces the identical receipt is idempotent; a second, different result
// for the same binding+source is rejected, whichever process attempts it.
// Receipt files are 0400 and never overwritten (same discipline as
// writeImmutableArtifact). Raw facts never enter this directory: a receipt
// carries digests and the resolved Policy result only.

const claimDir = (dir,binding) => path.join(dir,'claims',digest(binding));
const resultDir = (dir,binding) => path.join(dir,'results',digest(binding));

function writeCreateOnly(filename,value) {
  fs.mkdirSync(path.dirname(filename),{recursive:true,mode:0o700});
  const fd = fs.openSync(filename,'wx',0o400);
  try { fs.writeFileSync(fd,canonical(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

export function bindingDigest(binding) { return digest(binding); }

// Claim (binding, sourceId) for a finished receipt and persist the receipt.
// Returns {written:true} on first write, {written:false, idempotent:true}
// when the identical receipt was already handed off (a legitimate retry).
export function claimAndWrite(dir,receipt) {
  validateResult(receipt,receipt.binding);
  const binding = receipt.binding, sourceId = receipt.sourceId;
  const claimFile = path.join(claimDir(dir,binding),sourceId+'.json');
  const resultFile = path.join(resultDir(dir,binding),sourceId+'.json');
  const claim = {schema:1,kind:'SourceReceiptClaim',binding:structuredClone(binding),sourceId,resultDigest:receipt.resultDigest,rawFactDigest:receipt.rawFactDigest};
  try {
    writeCreateOnly(claimFile,claim);
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
    const existing = JSON.parse(fs.readFileSync(claimFile,'utf8'));
    if (!equal(existing,claim)) fail('duplicate source evaluation across processes: '+sourceId);
    // Identical claim already present: the matching result must also exist.
    const prior = JSON.parse(fs.readFileSync(resultFile,'utf8'));
    if (!equal(prior,receipt)) fail('receipt mismatch for claimed source: '+sourceId);
    return freeze({written:false,idempotent:true,claimFile,resultFile});
  }
  writeCreateOnly(resultFile,receipt);
  return freeze({written:true,idempotent:false,claimFile,resultFile});
}

// Gate/assembly side: read back every receipt for one binding and verify the
// claim set and the result set agree exactly with the canonical source list.
export function collectReceipts(dir,binding) {
  const out = new Map();
  for (const sourceId of EXPECTED_SOURCES) {
    const claimFile = path.join(claimDir(dir,binding),sourceId+'.json');
    const resultFile = path.join(resultDir(dir,binding),sourceId+'.json');
    if (!fs.existsSync(resultFile)) fail('source receipt missing: '+sourceId);
    const receipt = validateResult(JSON.parse(fs.readFileSync(resultFile,'utf8')),binding);
    if (!fs.existsSync(claimFile)) fail('source claim missing: '+sourceId);
    const claim = JSON.parse(fs.readFileSync(claimFile,'utf8'));
    if (claim.resultDigest !== receipt.resultDigest || claim.rawFactDigest !== receipt.rawFactDigest || !equal(claim.binding,binding)) fail('claim/receipt mismatch: '+sourceId);
    out.set(sourceId,receipt);
  }
  return out;
}

// Pending raw-fact envelopes for the two-process Kyverno source: each of its
// processes records only its own observations; whichever runs second (or the
// assembler) merges the parts and evaluates once. Parts carry cluster state
// only (no credentials, no decrypted data) and are bound to (source, build).
export function writePart(dir,part) {
  if (!object(part) || part.kind !== 'SourceObservationPart' || typeof part.source !== 'string' || typeof part.part !== 'string') fail('malformed observation part');
  const file = path.join(dir,'parts',part.source+'-'+part.part+'.json');
  fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
  const tmp = file+'.tmp-'+process.pid;
  fs.writeFileSync(tmp,canonical(part),{mode:0o600});
  fs.renameSync(tmp,file);
  return file;
}
export function readPart(dir,source,part) {
  const file = path.join(dir,'parts',source+'-'+part+'.json');
  if (!fs.existsSync(file)) return null;
  const value = JSON.parse(fs.readFileSync(file,'utf8'));
  if (value?.kind !== 'SourceObservationPart' || value.source !== source || value.part !== part) fail('observation part identity mismatch: '+source+'/'+part);
  return value;
}
export const receiptDigestOf = value => sha(canonical(value));
