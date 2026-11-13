import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {evaluate} from './engine.mjs';import {replayCommandParent} from './command-parent-replay.mjs';import {base,fixture,sha,read,analyzeFixture,parentShell} from './command-parent-fixtures.mjs';
const records=[];
function run(name,change,want,branch){test('complete original command parent '+name,async()=>{
 const input=fixture();change(input);const before=JSON.stringify(input),raw=await replayCommandParent(input),factBefore=JSON.stringify(raw),oldShell=parentShell(raw.operations.map(x=>x.execution.exitStatus)),old=oldShell.exitStatus===0?'PASS':'FAIL',p=evaluate({component:'semgrep-command-audit',status:'success',raw});
 assert.equal(old,want,raw.operations.at(-1).execution.diagnostic);assert.equal(p.decision,old);assert.equal(p.securityLevel,'standard');assert.deepEqual(p.rawEvidence,raw);assert.equal(JSON.stringify(input),before);assert.equal(JSON.stringify(raw),factBefore);
 if(raw.operations[0].execution.exitStatus)assert.equal(raw.operations.length,1,'original && must short-circuit');
 const file=name+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify({input,raw},null,2));records.push({name,branch,classification:'CONTROLLED_REPLAY',oldDecision:old,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),rawSha256:sha(factBefore),fixture:file,stageCount:raw.operations.length,originalParentShell:oldShell,diagnostic:raw.operations.at(-1).execution.diagnostic});
});}
run('healthy',()=>{},'PASS','healthy');
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({records},null,2)));

const pythonCases=[
 ['shell-input','import subprocess\nsubprocess.run(input(),shell=True)','FAIL','direct-shell'],
 ['os-system-input','import os\nos.system(input())','FAIL','direct-shell'],
 ['sys-argv-shell','import sys,os\nx=sys.argv[1]\nos.system(x)','FAIL','direct-shell'],
 ['flask-shell','from flask import request\nimport os\nx=request.args.get("cmd")\nos.system(x)','FAIL','direct-shell'],
 ['assignment-shell','import subprocess\nx=input()\nsubprocess.run("echo "+x,shell=True)','FAIL','direct-shell'],
 ['eval-input','eval(input())','FAIL','direct-shell'],
 ['argv-safe-argument','import subprocess\nsubprocess.run(["echo",input()])','PASS','safe-control'],
 ['constant-allowlist','import os\nx=input()\nif x not in ("date","uptime"):\n raise ValueError()\nos.system(x)','PASS','safe-control'],
 ['quoted-shell','import subprocess,shlex\nx=input()\nsubprocess.run("echo "+shlex.quote(x),shell=True)','PASS','safe-control'],
 ['environment-unconfirmed','import os\nos.system(os.getenv("ADMIN_COMMAND"))','PASS','unconfirmed'],
 ['wrapped-input-unknown','import os\ndef wrapper(): return input()\nos.system(wrapper())','PASS','unconfirmed'],
 ['shadowed-input','import os\ndef input(): return "date"\nos.system(input())','PASS','safe-control'],
 ['ssh-controlled-input','from controlled import remote\nremote(input())','FAIL','direct-ssh'],
 ['ssh-fixed-host','import subprocess\nsubprocess.run(["ssh","fixed-host",input()])','FAIL','direct-ssh'],
 ['ssh-argv-source','import sys\nfrom controlled import remote\nremote(sys.argv[1])','FAIL','direct-ssh'],
 ['ssh-quote-safe','import shlex\nfrom controlled import remote\nremote("printf %s "+shlex.quote(input()))','PASS','safe-control'],
 ['ssh-join-safe','import shlex\nfrom controlled import remote\nremote(shlex.join(["printf","%s",input()]))','PASS','safe-control'],
 ['ssh-file-origin-unknown','from pathlib import Path\nfrom controlled import remote\nremote(Path("operator-command").read_text())','PASS','unconfirmed'],
 ['ssh-dynamic-loaded-alias','import importlib.util\naudit=importlib.util.module_from_spec(spec)\naudit.remote(input())','PASS','unconfirmed'],
 ['shell-code-argv','import subprocess\nsubprocess.run(["sh","-c",input()])','FAIL','direct-interpreter'],
 ['python-code-argv','import subprocess\nsubprocess.run(["python3","-c",input()])','FAIL','direct-interpreter'],
 ['node-code-argv','import subprocess\nsubprocess.run(["node","-e",input()])','FAIL','direct-interpreter'],
 ['interpreter-stdin','import subprocess\nsubprocess.run(["python3","-"],input=input())','FAIL','direct-interpreter'],
 ['ssh-nested-join','import shlex\nfrom controlled import remote\nremote(shlex.join(["bash","-c",input()]))','FAIL','nested-interpreter'],
 ['ssh-nested-outer-quote','import shlex\nfrom controlled import remote\nremote("python3 -c "+shlex.quote(input()))','FAIL','nested-interpreter'],
 ['interpreter-environment','import subprocess,os\nsubprocess.run(["python3","-c",os.getenv("ADMIN_SCRIPT")])','PASS','unconfirmed'],
 ['interpreter-data-not-code','import subprocess\nsubprocess.run(["python3","-c","import sys;print(sys.argv[1])",input()])','PASS','safe-control'],
 ['interpreter-file-source-unknown','from pathlib import Path\nimport subprocess\nsubprocess.run(["sh","-c",Path("script").read_text()])','PASS','unconfirmed'],
 ['interpreter-quoted-code-unknown','import subprocess,shlex\nsubprocess.run(["python3","-c",shlex.quote(input())])','PASS','unconfirmed'],
 ['malformed-Python','def broken(:','FAIL','parser-error'],
];
for(const [name,source,want,branch]of pythonCases)run(name,r=>{r.python=analyzeFixture(source);r.audit.sourceText=source;},want,branch);
run('shell-inventory-only',r=>{r.python=analyzeFixture('bash -c "$OPERATOR_SCRIPT"','fixture.sh');r.audit.sourceFiles=['fixture.sh'];r.audit.sourceText='bash -c "$OPERATOR_SCRIPT"';},'PASS','unconfirmed');
run('mjs-inventory-only',r=>{r.python=analyzeFixture('const args=["node","-e",externalValue];','fixture.mjs');r.audit.sourceFiles=['fixture.mjs'];r.audit.sourceText='const args=["node","-e",externalValue];';},'PASS','unconfirmed');
run('historical-audit-report-replayed',r=>r.python={status:0,stdout:JSON.stringify(read(base+'historical/command-audit.json')),stderr:''},'PASS','historical-child');
const historical=read(base+'historical/semgrep-gate.json');
for(const id of ['java-http-runtime-exec','java-http-process-builder'])run(id,r=>r.semgrep.sourceReport.results=historical.commandTests.positive.filter(x=>x.check_id===id),'FAIL','direct-java');
run('Java-direct-FAIL-even-finding-mode-warn',r=>{r.mode='warn';r.semgrep.sourceReport.results=historical.commandTests.positive.filter(x=>x.check_id==='java-http-runtime-exec');},'FAIL','direct-java');
run('Java-generic-exec-is-warning-fact',r=>r.semgrep.sourceReport.results=historical.commandTests.positive.filter(x=>x.check_id==='java-runtime-exec'),'PASS','unconfirmed');
run('Java-generic-builder-is-warning-fact',r=>r.semgrep.sourceReport.results=historical.commandTests.positive.filter(x=>x.check_id==='java-process-builder'),'PASS','unconfirmed');
run('Java-unreviewed-rule-is-warning-fact',r=>r.semgrep.sourceReport.results=[{check_id:'existing-unreviewed-observation',path:'fixture.java',start:{line:1,col:1},extra:{severity:'ERROR',validation_state:'NO_VALIDATOR'}}],'PASS','unconfirmed');
run('Java-direct-low-severity-remains-warning',r=>r.semgrep.sourceReport.results=historical.commandTests.positive.filter(x=>x.check_id==='java-http-runtime-exec').map(x=>({...x,extra:{...x.extra,severity:'WARNING'}})),'PASS','unconfirmed');
run('existing-weak-cipher-parent-rule-not-removed',r=>r.semgrep.sourceReport.results=historical.fixtureResults.positive.filter(x=>x.check_id==='java-weak-cipher'),'FAIL','existing-parent-rule');
for(const id of ['command-audit','semgrep']){
 const audit=id==='command-audit';
 for(const key of ['create','ready','delete'])run(id+'-'+key+'-failed',r=>r[audit?'audit':'semgrep'][key]=false,'FAIL','lifecycle');
 run(id+'-replacement-UID-preserved',r=>r[audit?'audit':'semgrep'].currentUid='replacement','FAIL','identity');
}
run('audit-delete-wait-failure',r=>r.audit.deleteWait=false,'FAIL','lifecycle');
run('scanner-cleanup-incomplete',r=>r.semgrep.cleanup=false,'FAIL','lifecycle');
run('foreign-heavy-Lease',r=>r.runtime.leaseOwned=false,'FAIL','prerequisite');
run('manifest-hash-mismatch',r=>r.runtime.expectedManifestSha256='wrong','FAIL','prerequisite');
run('malformed-manifest',r=>r.runtime.manifest='{','FAIL','malformed');
run('semgrep-tool-hash-mismatch',r=>r.runtime.tools[Object.keys(r.runtime.tools).find(x=>!r.runtime.tools[x].symlink)].sha256='wrong','FAIL','prerequisite');
run('semgrep-tool-file-missing',r=>r.runtime.tools[Object.keys(r.runtime.tools)[0]]={error:'ENOENT'},'FAIL','prerequisite');
for(const k of ['securityProbe','sourceTransfer','sourceArchive','toolTransfer','fixtureWrites','find'])run('scanner-'+k+'-failure',r=>r.semgrep[k]=false,'FAIL','execution');
for(const key of ['canaryWorks','canaryListen','isolationDenied'])run(key+'-failed',r=>r.runtime[key]=false,'FAIL','isolation');
run('unmeasured-Jenkins-IP',r=>r.runtime.podIP='127.0.0.1','FAIL','isolation');
run('empty-Java-file-list',r=>r.semgrep.filesPerScan=0,'FAIL','missing');
run('unbounded-Java-file-list',r=>r.semgrep.filesPerScan=501,'FAIL','bounds');
run('Java-file-outside-target',r=>r.semgrep.unexpectedPath=true,'FAIL','identity');
for(const k of ['positive','negative','repeat','commandPositive','commandNegative','commandRepeat','sourceReport']){
 run(k+'-parser-error',r=>r.semgrep[k].errors=[{type:'ParseError'}],'FAIL','parser-error');
 run(k+'-malformed-JSON',r=>r.semgrep[k].rawText='{','FAIL','malformed');
 run(k+'-scanner-timeout',r=>r.semgrep[k].executionError=true,'FAIL','execution');
}
run('fixture-positive-detection-missing',r=>r.semgrep.positive.results=[],'FAIL','fixture-contract');
run('fixture-negative-unexpected-finding',r=>r.semgrep.negative.results=historical.fixtureResults.positive,'FAIL','fixture-contract');
run('command-fixture-direct-detection-missing',r=>r.semgrep.commandPositive.results=[],'FAIL','fixture-contract');
run('command-fixture-negative-unexpected',r=>r.semgrep.commandNegative.results=historical.commandTests.positive,'FAIL','fixture-contract');
run('command-fixture-repeat-drift',r=>r.semgrep.commandRepeat.results=[],'FAIL','fixture-contract');
for(const p of ['infra/messaging/dependencies.json','infra/security/command-audit.py','infra/security/script-command-policy.py','infra/security/ssh-command-policy.py','infra/security/interpreter-command-policy.py','infra/security/script-command-review.json','infra/security/ssh-command-review.json','.git-sha','infra/security/scan-rules.json'])run('read-failed-'+p.replaceAll('/','_'),r=>r.fileErrors[p]='ENOENT','FAIL','missing');
for(const key of ['write:.devsecops/command-audit.json','write:.devsecops/semgrep-native.json','write:.devsecops/semgrep-gate.json','mkdir:.devsecops'])run('IO-'+key.replaceAll('/','_'),r=>r.io[key]='ENOSPC','FAIL','io');
run('Python-no-JSON-output',r=>r.python={status:1,stdout:'',stderr:'python parser failed'},'FAIL','execution');
run('Python-invalid-report-JSON',r=>r.python={status:1,stdout:'{',stderr:'malformed'},'FAIL','malformed');
run('Python-JSON-null-report',r=>r.python={status:0,stdout:'null',stderr:''},'FAIL','malformed');
run('invalid-finding-mode',r=>r.mode='other','FAIL','configuration');
run('tracked-source-list-git-failure',r=>r.audit.gitFailure=true,'FAIL','execution');
run('memory-peak-operational-failure-not-success-report',r=>r.semgrep.memoryPeakFailure=true,'FAIL','execution');
run('Python-prerequisite-unavailable',r=>r.python={status:null,error:'ENOENT python',stdout:'',stderr:'python unavailable'},'FAIL','prerequisite');
run('historical-SSH-review-binding-is-inventory-not-bypass',r=>{const p=read(base+'historical/command-audit.json');p.ssh_audit.review_source_unchanged=false;r.python={status:0,stdout:JSON.stringify(p),stderr:''};},'PASS','existing-review-semantics');
run('zero-tracked-scripts-no-added-nonempty-rule',r=>{r.audit.sourceFiles=[];r.python=analyzeFixture('');},'PASS','existing-review-semantics');
for(const [name,mutate]of [['status-missing',p=>delete p.status],['status-failed',p=>p.status='failed']])run('Python-report-'+name,r=>{const p=JSON.parse(r.python.stdout);mutate(p);r.python.stdout=JSON.stringify(p);},'FAIL','missing');
// Whole-parent historical acceptance facts come from actual stage exit plus archived native reports.
test('real historical 270 complete parent acceptance',()=>{
 const raw=read(base+'historical-parent.json'),before=JSON.stringify(raw),oldShell=parentShell(raw.operations.map(x=>x.execution.exitStatus)),old=oldShell.exitStatus===0?'PASS':'FAIL',p=evaluate({component:'semgrep-command-audit',status:'success',raw});assert.equal(old,'PASS');assert.equal(p.decision,old);assert.deepEqual(p.rawEvidence,raw);assert.equal(JSON.stringify(raw),before);const file='historical-parent.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify(raw,null,2));records.push({name:'historical-270',branch:'historical-parent',classification:'REAL_HISTORICAL',oldDecision:old,standardDecision:p.decision,rawPreserved:true,rawSha256:sha(before),fixture:file});
});
for(const [name,change]of [['incomplete',r=>r.complete=false],['wrong-command',r=>r.command='other'],['missing-Semgrep-after-audit-success',r=>r.operations.pop()],['missing-command-status',r=>delete r.operations[0].execution.exitStatus],['missing-reports',r=>delete r.operations[0].reports]])test('missing full command-parent facts '+name,async()=>{const raw=await replayCommandParent(fixture());change(raw);const p=evaluate({component:'semgrep-command-audit',status:'success',raw});assert.equal(p.status,'NOT_TESTED');assert.equal(p.decision,null);});
test('Policy never re-runs source analysis and never counts Semgrep twice',async()=>{
 const raw=await replayCommandParent(fixture()),before=JSON.stringify(raw),p=evaluate({component:'semgrep-command-audit',status:'success',raw});assert.equal(p.decision,'PASS');assert.equal(p.normalizedFacts.operations.length,2);assert.equal(JSON.stringify(p.normalizedFacts.operations),JSON.stringify(raw.operations));assert.equal(JSON.stringify(raw),before);const code=fs.readFileSync('infra/security/policy/command-parent.mjs','utf8');assert.ok(!/from ['"].*(?:semgrep-policy|child_process|replay)/.test(code));assert.ok(!/analyzeFixture|classifySemgrep\(/.test(code));
});
test('no inspected command actually executes',()=>{const r=analyzeFixture('import subprocess\nsubprocess.run(["python3","-c",input()])');const p=JSON.parse(r.stdout);assert.equal(p.policyTests.executed_commands,0);assert.equal(p.ssh_audit.tests.executed_commands,0);assert.equal(p.interpreter_audit.tests.executed_commands,0);assert.ok(p.blockingFindings.length);});
test('low/strict/audit override cannot soften the frozen command parent',async()=>{const input=fixture();input.audit.ready=false;const raw=await replayCommandParent(input);for(const config of [{securityLevel:'low'},{securityLevel:'strict'},{mode:'audit',componentOverrides:{'semgrep-command-audit':{High:'PASS'}}}])assert.equal(evaluate({component:'semgrep-command-audit',status:'success',raw},config).decision,'FAIL');});
run('Semgrep-missing-native-result-shape',r=>r.semgrep.sourceReport.rawText='{}','FAIL','missing');
test('successful command execution without native report is NOT_TESTED',async()=>{const raw=await replayCommandParent(fixture());raw.operations[0].reports={};assert.equal(evaluate({component:'semgrep-command-audit',status:'success',raw}).status,'NOT_TESTED');});
