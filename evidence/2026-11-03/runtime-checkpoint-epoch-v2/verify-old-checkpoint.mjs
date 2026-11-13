import fs from 'node:fs';import path from 'node:path';
import {verifyCheckpoint} from '../runtime-14-checkpoint-guard-review/verify-checkpoint.mjs';
const base=path.dirname(new URL(import.meta.url).pathname),root=path.resolve(base,'../../..');
const anchor=JSON.parse(fs.readFileSync(path.join(root,'evidence/2026-11-03/runtime-14-checkpoint-guard-review/checkpoint-digest.json')));
const result=verifyCheckpoint({root,checkpointPath:anchor.checkpointPath,expectedSha256:anchor.sha256});
if(result.status!=='FAILED'||result.integrityStatus!=='VERIFIED'||result.acceptedWiredCount!==14)throw Error('OLD_CHECKPOINT_CHANGED');
fs.writeFileSync(path.join(base,'old-checkpoint-integrity.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result));
