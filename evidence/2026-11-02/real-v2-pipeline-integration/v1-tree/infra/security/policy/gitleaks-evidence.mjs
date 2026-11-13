import crypto from 'node:crypto';
const fail=message=>{throw Error('POLICY_ERROR: Gitleaks '+message);};
// The input carries redacted locations and exact source-line hashes, never secret text.
// Review acceptance uses the same path/rule/line-SHA binding as source-gate.mjs.
export function gitleaksEvidence(raw){
 if(!raw||!Array.isArray(raw.findings)||!Array.isArray(raw.reviewedEntries)||!Array.isArray(raw.sourceLines)||typeof raw.sourcePrefix!=='string'||!raw.sourcePrefix.endsWith('/'))fail('incomplete source/review evidence');
 const observations=raw.findings.map(f=>{
  if(typeof f.file!=='string'||typeof f.rule!=='string'||!Number.isInteger(f.line)||f.line<1)fail('invalid location');
  const relative=f.file.replace(new RegExp('^'+raw.sourcePrefix.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')),'');
  if(relative===f.file||relative.includes('..'))fail('unexpected scanner file path');
  const line=raw.sourceLines.find(x=>x.path===relative&&x.line===f.line);
  if(!line||!/^[a-f0-9]{64}$/.test(line.sha256??''))fail('exact source line hash missing');
  const review=raw.reviewedEntries.find(x=>x.path===relative&&x.rule===f.rule&&x.line_sha256===line.sha256);
  return {finding:structuredClone(f),sourceLineSha256:line.sha256,reviewMatched:!!review,reviewReason:review?.reason??null};
 });
 return {component:'gitleaks',status:'success',observations};
}
export const lineSha256=text=>crypto.createHash('sha256').update(text).digest('hex');
