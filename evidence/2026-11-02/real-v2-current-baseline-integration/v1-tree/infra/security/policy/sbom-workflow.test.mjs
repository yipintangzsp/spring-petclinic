import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {evaluate} from './engine.mjs';import {base,sha,fixture,oracle,config} from './sbom-test-harness.mjs';
const known=['gitleaks','semgrep','sonarqube','sbom','trivy','cosign','kubescape','zap','defectdojo','provenance','build-provenance'],records=[],cases=[];
function row(name,mutate,want,production=false){const raw={cfg:production?{adapter:'petclinic',mode:'enforce'}:{mode:'enforce',profile:'java-web',runtimeRevision:'a'.repeat(40),sourceCommit:'a'.repeat(40),sbomFile:'bom.json',disabledModules:known.filter(x=>x!=='sbom')},steps:Object.fromEntries(['checkout','credentials','module-stage','gate','config-write','manager-write','source-write','summary-script-write','archive','scan-sh','lease-acquire','lease-release','summary-inert-step','setup-sh'].map(k=>[k,{}]))},operation=fixture(production?'production':'generic');mutate(raw,operation);cases.push({name,raw,operation,want});}
for(const mode of ['audit','enforce']){
 row(mode+'-valid',r=>r.cfg.mode=mode,'PASS');
 row(mode+'-missing-file',(r,o)=>{r.cfg.mode=mode;o.files['/fixture/project/bom.json']={error:'ENOENT'};},'FAIL');
 row(mode+'-not-configured',r=>{r.cfg.mode=mode;delete r.cfg.sbomFile;},mode==='enforce'?'FAIL':'NOT_CONFIGURED');
 row(mode+'-disabled',r=>{r.cfg.mode=mode;r.cfg.disabledModules.push('sbom');},'SKIPPED');
 for(const step of ['checkout','credentials','module-stage','gate','config-write','manager-write','source-write','summary-script-write','archive','scan-sh','lease-acquire','lease-release','summary-inert-step','setup-sh'])row(mode+'-exception-'+step,r=>{r.cfg.mode=mode;r.steps[step]={error:'controlled wrapper failure'};},'FAIL');
}
row('off-SKIPPED',r=>r.cfg.mode='off','SKIPPED');
row('module-switch-false-SKIPPED',r=>r.cfg.moduleEnabled={sbom:false},'SKIPPED');
row('production-valid',()=>{},'PASS',true);
row('production-Maven-fails',(_,o)=>o.generator.status=1,'FAIL',true);
row('production-verify-fails',(_,o)=>o.extraction.status=1,'FAIL',true);
row('production-disabled-rejected',r=>r.cfg.disabledModules=['sbom'],'FAIL',true);
row('production-audit-rejected',r=>r.cfg.mode='audit','FAIL',true);
row('invalid-profile',r=>r.cfg.profile='unknown','FAIL');
row('runtime-revision-missing',r=>delete r.cfg.runtimeRevision,'FAIL');
const prepared=[];for(const c of cases){const old=await oracle(c.operation);c.operationExitCode=old.code;prepared.push({name:c.name,raw:c.raw,operationExitCode:c.operationExitCode});}
const jar=process.env.PROVENANCE_GROOVY_JAR||'/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar';assert.equal(sha(fs.readFileSync(jar)),'de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sbom-groovy-'));let old;
try{const p=path.join(dir,'input.json');fs.writeFileSync(p,JSON.stringify(prepared));const result=spawnSync('java',['-Xmx192m','-cp',jar,'groovy.ui.GroovyMain','infra/security/policy/sbom-workflow-oracle.groovy',p],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});assert.equal(result.status,0,result.stderr);old=JSON.parse(result.stdout);}finally{fs.rmSync(dir,{recursive:true,force:true});}
for(const c of cases)test('original Manager SBOM wrapper '+c.name,()=>{
 const r=old.find(x=>x.name===c.name),decision=r.failed?'FAIL':['disabled','skipped'].includes(r.moduleStatus)?'SKIPPED':r.moduleStatus==='not_configured'?'NOT_CONFIGURED':r.moduleStatus==='warn'?'WARN':r.moduleStatus==='success'?'PASS':'FAIL';assert.equal(decision,c.want,r.reason);
 const facts={stage:'workflow',classification:'CONTROLLED_REPLAY',complete:true,execution:{failed:r.failed,reason:r.reason,operationExitCode:c.operationExitCode},moduleStatus:r.moduleStatus,module:r.module,observations:r.trace,files:{},io:{}},before=JSON.stringify(facts),p=evaluate({component:'sbom',status:'success',raw:facts});assert.equal(p.decision??p.status,decision);assert.equal(JSON.stringify(facts),before);assert.deepEqual(p.rawEvidence,facts);
 records.push({name:c.name,classification:'CONTROLLED_REPLAY',oldDecision:decision,standardDecision:p.decision??p.status,rawPreserved:true,originalGroovyExecuted:true,inputSha256:sha(before),scope:r.scope});fs.writeFileSync(base+'fixtures/workflow--'+c.name+'.json',JSON.stringify({facts,input:c.raw,operation:c.operation,legacy:r},null,2));
});
test.after(()=>fs.writeFileSync(base+'workflow-differential.json',JSON.stringify({records},null,2)));
