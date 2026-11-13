import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {evaluate} from './engine.mjs';import {replayPromotion} from './promotion-replay.mjs';import {fixture,base,sha} from './promotion-fixtures.mjs';
const cases=[],records=[];const good=fixture('dry-run');
function row(name,change,want){const r={name,action:'dry-run',initialResult:'SUCCESS',stepErrors:{},codes:{evidence:0,sign:0,promote:0,preflight:0,privateMain:0},approvedDigest:good.approval.approvedDigest,want};change(r);cases.push(r);}
row('dry-run-all-success',()=>{},'PASS');row('deploy-all-success',r=>r.action='deploy','PASS');row('audit-only-SKIPPED',r=>r.action='audit-only','SKIPPED');row('failed-build-SKIPPED',r=>r.initialResult='FAILURE','SKIPPED');row('unstable-build-SKIPPED',r=>r.initialResult='UNSTABLE','SKIPPED');
for(const phase of ['evidence','sign','promote'])row('upstream-'+phase+'-fails',r=>r.codes[phase]=1,'FAIL');
for(const stage of ['Candidate Approval Evidence','Candidate Sign and Approve','Approved Promotion'])for(const type of ['stage','credentials','environment','sh'])row(type+'-'+stage+'-exception',r=>r.stepErrors[type+':'+stage]='controlled Jenkins DSL error','FAIL');
row('private-main-parent-success',r=>r.variant='private-main','PASS');
row('private-main-preflight-failure',r=>{r.variant='private-main';r.codes.preflight=1;},'FAIL');
row('private-main-command-failure',r=>{r.variant='private-main';r.codes.privateMain=1;},'FAIL');
row('private-main-credentials-failure',r=>{r.variant='private-main';r.stepErrors['credentials:Git Promotion']='controlled credential failure';},'FAIL');
const jar=process.env.PROVENANCE_GROOVY_JAR||'/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar';assert.equal(sha(fs.readFileSync(jar)),'de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'promotion-groovy-'));let original;
try{const p=path.join(temp,'rows.json');fs.writeFileSync(p,JSON.stringify(cases));const r=spawnSync('java',['-Xmx192m','-cp',jar,'groovy.ui.GroovyMain','infra/security/policy/promotion-workflow-oracle.groovy',p],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});assert.equal(r.status,0,r.stderr);original=JSON.parse(r.stdout);}finally{fs.rmSync(temp,{recursive:true,force:true});}
for(const c of cases)test('original Promotion stage eligibility '+c.name,()=>{
 const old=original.find(x=>x.name===c.name),decision=old.failed?'FAIL':!old.selected.length?'SKIPPED':'PASS';assert.equal(decision,c.want,old.reason);const raw={schema:1,stage:'eligibility',complete:true,classification:'CONTROLLED_REPLAY',conditions:{selected:old.selected.length>0,stages:old.selected,action:c.action,initialResult:c.initialResult},execution:{failed:old.failed,reason:old.reason},observations:old.commands},before=JSON.stringify(raw),p=evaluate({component:'security-approval-promotion',status:'success',raw});assert.equal(p.decision??p.status,decision);assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);const file='workflow--'+c.name+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify(raw,null,2));records.push({name:c.name,stage:'eligibility',classification:'CONTROLLED_REPLAY',oldDecision:decision,standardDecision:p.decision??p.status,rawPreserved:true,rawSha256:sha(before),fixture:file,originalGroovyExecuted:true});
});
test.after(()=>fs.writeFileSync(base+'workflow-differential.json',JSON.stringify({records},null,2)));
