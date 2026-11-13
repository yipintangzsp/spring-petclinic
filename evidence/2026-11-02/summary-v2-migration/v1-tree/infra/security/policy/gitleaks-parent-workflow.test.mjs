import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {evaluate} from './engine.mjs';import {base,sha} from './gitleaks-parent-fixtures.mjs';
const cases=[],records=[];
const add=(name,code=0,steps={},cfg={})=>cases.push({name,operationExitCode:code,raw:{cfg:{mode:'enforce',adapter:'petclinic',profile:'java-web',project:'fixture',...cfg},steps}});
for(const code of [0,1,2,10,20,127,137,143])add('parent-exit-'+code,code);
for(const key of ['module-stage','credentials','scan-sh','gate','manager-write','archive'])add('wrapper-error-'+key,0,{[key]:{error:'controlled '+key+' error'}});
add('frozen-production-off-rejected',0,{}, {mode:'off'});
add('frozen-production-audit-rejected',0,{}, {mode:'audit'});
add('frozen-production-disable-rejected',0,{}, {disabledModules:['gitleaks']});
add('wrong-profile-rejected',0,{}, {profile:'unknown'});
add('invalid-switch-rejected',0,{}, {moduleEnabled:{gitleaks:'false'}});
const jar=process.env.PROVENANCE_GROOVY_JAR||'/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar';
assert.equal(sha(fs.readFileSync(jar)),'de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gitleaks-parent-groovy-'));let old;
try{const file=path.join(dir,'rows.json');fs.writeFileSync(file,JSON.stringify(cases));const r=spawnSync('java',['-Xmx192m','-cp',jar,'groovy.ui.GroovyMain','infra/security/policy/gitleaks-parent-workflow-oracle.groovy',file],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});assert.equal(r.status,0,r.stderr);old=JSON.parse(r.stdout);}finally{fs.rmSync(dir,{recursive:true,force:true});}
for(const c of cases)test('Gitleaks original selected Manager aggregation: '+c.name,()=>{
 const r=old.find(x=>x.name===c.name);assert.ok(r);const decision=r.failed?'FAIL':'PASS';
 const raw={schema:1,stage:'wrapper',complete:true,classification:'CONTROLLED_REPLAY',execution:{failed:r.failed,reason:r.reason},module:r.module,observations:r.trace},before=JSON.stringify(raw);
 const result=evaluate({component:'gitleaks',status:'success',raw},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(result.decision,decision);assert.deepEqual(result.rawEvidence,raw);assert.equal(JSON.stringify(raw),before);
 const file='wrapper--'+c.name+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify({input:c,facts:raw},null,2));
 records.push({name:c.name,branch:'parent-aggregation',classification:'CONTROLLED_REPLAY',oldDecision:decision,standardDecision:result.decision,rawPreserved:true,rawSha256:sha(before),fixture:file,originalGroovyExecuted:true,module:r.module??null});
});
test.after(()=>fs.writeFileSync(base+'workflow-differential.json',JSON.stringify({scope:'Actual unchanged Security Manager executed with inert Jenkins DSL; resource list selected to Gitleaks only. No CPS, credentials, scanner, Summary script or remote action.',records},null,2)));
