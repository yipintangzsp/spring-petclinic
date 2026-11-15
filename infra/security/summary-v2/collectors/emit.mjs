import {createSourceOwner} from '../owner.mjs';
import {claimAndWrite} from '../receipts.mjs';
import {runBinding,receiptsDir} from './context.mjs';

// Final step of every runtime collector (T08a / C1+C2): evaluate the captured
// facts through a fresh source owner and hand the resulting receipt off via
// the cross-process claim protocol. Collection is passive: this function
// NEVER throws and never changes the production module's exit code or IO.
// It returns a status object so tests and true-run harnesses can verify the
// handoff; production callers ignore the return value.
//
// Boundary: emission happens from the production modules' existing report
// points. A failure before a module reaches its report point (missing lease,
// missing credential, missing tool) produces no report today and therefore
// no receipt either; the assembler reports that source as missing, which is
// the same fact the V1 summary records from the module's exit code.
export async function emitReceipt(sourceId,facts,{root = '.',config = {},binding = null,dir = null} = {}) {
  try {
    const bound = binding ?? runBinding(root);
    if (!bound) return {emitted:false,reason:'run binding unavailable'};
    const owner = createSourceOwner(bound);
    const receipt = await owner.evaluateOnce(sourceId,facts,config);
    const out = claimAndWrite(dir ?? receiptsDir(root),receipt);
    return {emitted:true,receipt,...out};
  } catch (e) {
    return {emitted:false,reason:String(e?.message ?? e)};
  }
}
