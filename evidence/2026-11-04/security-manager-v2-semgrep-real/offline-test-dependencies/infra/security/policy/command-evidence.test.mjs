import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {spawnSync} from 'node:child_process';import {evaluate} from './engine.mjs';import {commandRunFacts} from './command-evidence.mjs';
const root='infra/security/',entry=fs.readFileSync(root+'command-audit.mjs','utf8');
const encoded=entry.match(/const script=("(?:[^"\\]|\\.)*");/)[1],script=JSON.parse(encoded),records=[];
const inputs=[
 ['fixed','import subprocess\nsubprocess.run(["date"])','PASS'],
 ['unknown-environment','import subprocess,os\nsubprocess.run(["python3","-c",os.getenv("ADMIN_SCRIPT")])','PASS'],
 ['direct-shell-input','import subprocess\nsubprocess.run(input(),shell=True)','FAIL'],
 ['direct-interpreter-input','import subprocess\nsubprocess.run(["python3","-c",input()])','FAIL'],
 ['parse-error','def broken(:','FAIL']
];
for(const [name,source,expected]of inputs)test('original static analyzer differential: '+name,()=>{
 const payload={code:fs.readFileSync(root+'command-audit.py','utf8'),policy:fs.readFileSync(root+'script-command-policy.py','utf8'),ssh_policy:fs.readFileSync(root+'ssh-command-policy.py','utf8'),interpreter_policy:fs.readFileSync(root+'interpreter-command-policy.py','utf8'),files:{'fixture.py':source},review:{items:[]},ssh_review:{source_binding:{}}};
 // Execute only the existing parser/policy code, never inspected source text.
 const p=spawnSync('python3',['-B','-c',script],{input:JSON.stringify(payload),encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
 assert.ok([0,1].includes(p.status),p.stderr);let old;try{old=JSON.parse(p.stdout).status==='success'?'PASS':'FAIL';}catch{old='FAIL';}
 const run={exitStatus:p.status,stdout:p.stdout,stderr:p.stderr},before=JSON.stringify(run),facts=commandRunFacts(run);assert.equal(old,expected);
 const result=evaluate(facts);assert.equal(result.decision,old);assert.equal(JSON.stringify(run),before);if(facts.status!=='error')assert.deepEqual(result.frozenEvidence.rawEvidence,facts.raw);
 records.push({case:name,kind:'synthetic-static-fixture-no-inspected-code-execution',legacy:old,standard:result.decision,rawUnchanged:true});
});
test.after(()=>fs.writeFileSync('evidence/2026-11-01/remaining-policy/command-differential.json',JSON.stringify({records},null,2)));
