import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';
import {gitleaksEvidence,lineSha256} from './gitleaks-evidence.mjs';import {evaluate} from './engine.mjs';
const source=fs.readFileSync('infra/security/source-gate.mjs','utf8');
// Execute the actual unchanged legacy review loop, not a rewritten expected decision.
const start=source.indexOf(' const lines=new Map();report.sourceScan.verifiedFalsePositives=[];'),end=source.indexOf(' const peak=',start);
assert.ok(start>0&&end>start);
const legacy=source.slice(start,end);
function oracle(raw,text){
 const report={sourceScan:{findings:structuredClone(raw.findings)}};
 const context={report,reviewed:raw.reviewedEntries,crypto,exec:args=>({stdout:text[args[1]]})};
 try{vm.runInNewContext(legacy,context);return {decision:'PASS',report};}catch(e){return {decision:'FAIL',error:e.message,report};}
}
const f={rule:'fixture-rule',file:'/fixture/src/a.txt',line:1,fingerprint:'synthetic'},text='public checksum fixture';
function fixture(){return {findings:[{...f}],sourcePrefix:'/fixture/src/',sourceLines:[{path:'a.txt',line:1,sha256:lineSha256(text)}],reviewedEntries:[{path:'a.txt',rule:f.rule,line_sha256:lineSha256(text),reason:'reviewed synthetic public checksum'}]};}
// Oracle original prefix remains fixed in frozen source; test inputs use its prefix.
function oldInput(raw){const x=structuredClone(raw);x.sourcePrefix='/work/source/';x.findings.forEach(f=>f.file=f.file.replace('/fixture/src/','/work/source/'));return x;}
const records=[];
for(const [name,mutate]of [
 ['reviewed',()=>{}],['new-finding',r=>r.reviewedEntries=[]],['changed-line',r=>r.sourceLines[0].sha256=lineSha256('changed')],['changed-rule',r=>r.findings[0].rule='other'],['changed-review-path',r=>r.reviewedEntries[0].path='other.txt'],['zero-findings',r=>r.findings=[]],['duplicate-finding',r=>r.findings.push({...r.findings[0]})]
])test('frozen Gitleaks differential: '+name,()=>{
 const raw=fixture();mutate(raw);const old=oldInput(raw),line=raw.sourceLines[0].sha256===lineSha256(text)?text:'changed';
 const before=JSON.stringify(raw);const expected=oracle(old,{'/work/source/a.txt':line});const actual=evaluate({component:'gitleaks',status:'success',raw});
 assert.equal(actual.decision,expected.decision);assert.equal(JSON.stringify(raw),before);
 assert.deepEqual(gitleaksEvidence(raw).observations.map(o=>o.finding),raw.findings);
 records.push({case:name,legacy:expected.decision,standard:actual.decision,inputUnchanged:before===JSON.stringify(raw)});
});
test('missing source evidence and path escape fail explicitly',()=>{
 for(const change of [r=>r.sourceLines=[],r=>r.findings[0].file='/elsewhere/a.txt',r=>r.findings[0].file='/fixture/src/../a.txt']){
  const raw=fixture();change(raw);assert.throws(()=>gitleaksEvidence(raw),/POLICY_ERROR/);
 }
});
test.after(()=>fs.writeFileSync('evidence/2026-11-01/policy-engine/gitleaks-differential.json',JSON.stringify({legacySourceSha256:lineSha256(source),records},null,2)));
