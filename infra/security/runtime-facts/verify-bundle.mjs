import fs from 'node:fs';import crypto from 'node:crypto';
const d=JSON.parse(fs.readFileSync('runtime-source-bundle.json'));
if(d.schema!==1||!d.files||!d.sourceIdentity)throw Error('Source bundle identity missing');
for(const [p,h] of Object.entries(d.files)){
  if(p.startsWith('/')||p.split('/').includes('..')||fs.lstatSync(p).isSymbolicLink())throw Error('Source bundle path unsafe');
  if(crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')!==h)throw Error('Source bundle hash mismatch: '+p);
}
console.log('Exact uploaded source identities verified; non-release only');
