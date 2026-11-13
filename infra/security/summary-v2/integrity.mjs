import fs from 'node:fs';
import path from 'node:path';
import {equal,fail,sha} from './codec.mjs';

// Contract and selected version come from trusted checkout/owner configuration,
// NEVER from artifact claims. No probing V1 as a permissive fallback.
export function verifyVersion({root,contract,selectedVersion,consumerVersion,producer}) {
  if (contract.schema !== 1 || !['V1','V2'].includes(selectedVersion)) fail('unknown selected version');
  const selected = contract.versions[selectedVersion];
  if (!selected || !selected.consumers.includes(consumerVersion)) fail('unsupported mixed version');
  if (!equal(selected.producer,producer)) fail('unknown producer identity');
  const checked = [];
  for (const [relative,expected] of Object.entries(selected.files)) {
    const full = path.resolve(root,relative),base = path.resolve(root)+path.sep;
    if (!full.startsWith(base) || fs.lstatSync(full).isSymbolicLink()) fail('integrity path');
    if (sha(fs.readFileSync(full)) !== expected) fail('tampered version file: '+relative);
    checked.push(relative);
  }
  return {selectedVersion,consumerVersion,checked};
}
