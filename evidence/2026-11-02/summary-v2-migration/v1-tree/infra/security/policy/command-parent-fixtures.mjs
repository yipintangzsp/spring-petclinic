import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';import crypto from 'node:crypto';
export const base='evidence/2026-11-01/command-parent/',read=p=>JSON.parse(fs.readFileSync(p)),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const entry=fs.readFileSync('infra/security/command-audit.mjs','utf8'),script=JSON.parse(entry.match(/const script=("(?:[^"\\]|\\.)*");/)[1]);
export function analyzeFixture(source,name='fixture.py'){
 const payload={code:fs.readFileSync('infra/security/command-audit.py','utf8'),policy:fs.readFileSync('infra/security/script-command-policy.py','utf8'),ssh_policy:fs.readFileSync('infra/security/ssh-command-policy.py','utf8'),interpreter_policy:fs.readFileSync('infra/security/interpreter-command-policy.py','utf8'),files:{[name]:source},review:{items:[]},ssh_review:{source_binding:{}}};
 const r=spawnSync('python3',['-B','-c',script],{input:JSON.stringify(payload),encoding:'utf8',timeout:10000,maxBuffer:2*1024*1024});return {status:r.status,stdout:r.stdout,stderr:r.stderr,error:r.error?String(r.error):null,classification:'CONTROLLED_REPLAY_STATIC_ANALYSIS_ONLY',payload};
}
let defaultAnalysis;
export function fixture(){
 const h=read(base+'historical/semgrep-gate.json'),manifest=fs.readFileSync('infra/security/scanner-tools.json','utf8'),tools=JSON.parse(manifest);
 return {classification:'CONTROLLED_REPLAY',build:'270',mode:'enforce',source:'a'.repeat(40),python:structuredClone(defaultAnalysis??=(analyzeFixture('import subprocess\nsubprocess.run(["date"])'))),runtime:{manifest,expectedManifestSha256:sha(manifest),tools:Object.fromEntries(tools.files.filter(x=>x.path==='semgrep'||x.path.startsWith('semgrep/')).map(x=>[x.path,{sha256:x.sha256,symlink:x.symlink}])),leaseOwned:true,podIP:'10.42.0.10',canaryWorks:true,canaryListen:true,isolationDenied:true},audit:{sourceFiles:['fixture.py'],sourceText:'import subprocess\nsubprocess.run(["date"])',create:true,ready:true,uid:'audit-uid',currentUid:'audit-uid',delete:true,deleteWait:true},semgrep:{create:true,ready:true,uid:'scanner-uid',currentUid:'scanner-uid',delete:true,cleanup:true,securityProbe:true,toolTransfer:true,sourceTransfer:true,sourceArchive:true,fixtureWrites:true,find:true,positive:{results:h.fixtureResults.positive,errors:[]},negative:{results:[],errors:[]},repeat:{results:h.fixtureResults.repeat,errors:[]},commandPositive:{results:h.commandTests.positive,errors:[]},commandNegative:{results:[],errors:[]},commandRepeat:{results:h.commandTests.repeat,errors:[]},sourceReport:{results:[],errors:[]},filesPerScan:1},io:{},fileErrors:{}};
}

export function parentShell(codes){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'command-parent-shell-'));
 try{
  fs.writeFileSync(path.join(dir,'node'),'#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRACE"\ncase "$1" in infra/security/command-audit.mjs) exit "$AUDIT_RC";; *) exit "$SEMGREP_RC";; esac\n',{mode:0o700});
  const command=read('resources/security-manager/petclinic-adapter.json').find(x=>x.id==='semgrep').command,trace=path.join(dir,'trace'),r=spawnSync('/bin/sh',['-c',command],{cwd:dir,env:{PATH:dir,TRACE:trace,AUDIT_RC:String(codes[0]),SEMGREP_RC:String(codes[1]??0)},encoding:'utf8',timeout:5000});return {exitStatus:r.status,command,trace:fs.existsSync(trace)?fs.readFileSync(trace,'utf8').trim().split('\n'):[]};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
