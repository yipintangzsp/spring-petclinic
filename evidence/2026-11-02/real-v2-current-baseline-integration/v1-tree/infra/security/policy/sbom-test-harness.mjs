import fs from 'node:fs';import crypto from 'node:crypto';import path from 'node:path';import vm from 'node:vm';import os from 'node:os';import {spawnSync} from 'node:child_process';
import {sbomObservations,MissingSbomEvidence} from './sbom-observations.mjs';
export const base='evidence/2026-11-01/sbom-parent/',sha=x=>crypto.createHash('sha256').update(x).digest('hex'),read=p=>JSON.parse(fs.readFileSync(p)),bom=fs.readFileSync(base+'historical/production-270/sbom.json'),summary=read(base+'historical/production-270/sbom-summary.json'),genericBom=fs.readFileSync(base+'historical/generic-4/sbom-native.json','utf8');
const script=fs.readFileSync('infra/security/sbom-verify.mjs','utf8').replace(/^import .*;\s*$/gm,''),manager=fs.readFileSync('infra/security/manager/tool.mjs','utf8').replace(/^import .*;\s*$/gm,''),runtime=fs.readFileSync('infra/security/scanner-runtime.mjs','utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
export function fixture(stage){const manifest=fs.readFileSync('infra/security/scanner-tools.json','utf8');return {stage,classification:'CONTROLLED_REPLAY',now:Date.parse(summary.createdAt),environment:{BUILD_NUMBER:'270',HEAVY_HOLDER:'fixture-holder'},generator:{status:0,stdout:'Historical generator observation reused; no actual Maven'},extraction:{status:0,base64:bom.toString('base64')},files:{'target/classes/META-INF/sbom/application.cdx.json':{value:bom.toString('base64')},'.git-sha':{value:summary.source},'.devsecops/manager-config.json':{value:JSON.stringify({sourceRoot:'/fixture/project',sbomFile:'bom.json',build:270,project:'fixture',mode:'enforce'})},'/fixture/project/bom.json':{value:bom.toString()}},io:Object.fromEntries(['output-mkdir','sbom-write','summary-write','native-write','manager-report-write'].map(k=>[k,{}])),runtime:{manifest,expectedManifestSha256:sha(manifest),lease:{status:0,stdout:JSON.stringify({spec:{holderIdentity:'fixture-holder'}})}}};}
export function changeBom(r,change){const b=JSON.parse(Buffer.from(r.extraction.base64,'base64'));change(b);const bytes=Buffer.from(JSON.stringify(b));r.extraction.base64=bytes.toString('base64');r.files['target/classes/META-INF/sbom/application.cdx.json'].value=r.extraction.base64;r.files['/fixture/project/bom.json'].value=bytes.toString();}
export function config(r,change){const c=JSON.parse(r.files['.devsecops/manager-config.json'].value);change(c);r.files['.devsecops/manager-config.json'].value=JSON.stringify(c);}
export async function oracle(r){
 const f=sbomObservations(r),writes={},process={argv:['node','frozen','sbom'],env:r.environment};let complete=true;
 class FixedDate extends Date{constructor(...a){super(...(a.length?a:[r.now]));}}
 const fakeFs={readFileSync:(p,encoding)=>{
  if(p==='infra/security/scanner-tools.json'){if(r.runtime.manifestReadError)throw Error(r.runtime.manifestReadError);return r.runtime.manifest;}
  if(p==='infra/security/tools-lock.json'){if(r.runtime.lockReadError)throw Error(r.runtime.lockReadError);return JSON.stringify({supplyChain:{scanner_manifest_sha256:r.runtime.expectedManifestSha256}});}
  const v=f.file(p);return p==='target/classes/META-INF/sbom/application.cdx.json'?Buffer.from(v,'base64'):encoding?v:Buffer.from(v);
 },mkdirSync:()=>f.io('output-mkdir'),writeFileSync:(p,v)=>{f.io(p.endsWith('sbom-summary.json')?'summary-write':p.endsWith('sbom-native.json')?'native-write':p.endsWith('sbom-manager.json')?'manager-report-write':'sbom-write');writes[p]=String(v);}};
 const context={fs:fakeFs,crypto,path,process,Buffer,Date:FixedDate,console:{log:()=>{}},execFileSync:(tool,args)=>{f.need(r.extraction,'status');if(r.extraction.error||r.extraction.status!==0)throw Error('JAR SBOM extraction failed');return Buffer.from(f.need(r.extraction,'base64'),'base64');},spawnSync:()=>r.runtime.lease};
 let code=0,reason;
 try{
  if(r.stage==='generic'){
   const h=vm.runInNewContext('(function(){'+runtime+';return {requireLease,toolchain,verifyTools};})()',context);Object.assign(context,h);await vm.runInNewContext('(async()=>{'+manager+'})()',context);code=process.exitCode??0;
  }else{
   if(r.stage==='production'&&(r.generator.error||r.generator.status!==0)){code=r.generator.status||1;reason='Maven SBOM generation failed';}
   if(!code)vm.runInNewContext(script,context);
  }
 }catch(error){code=1;reason=error.message;if(error instanceof MissingSbomEvidence)complete=false;}
 return {decision:complete?(code===0?'PASS':'FAIL'):null,code,reason,writes,trace:f.trace};
}
// Run the exact production shell && expression with inert executables. The real generator/verifier is never invoked.
export function shellOracle(generatorStatus,verifierStatus){
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'sbom-shell-')),command=read('resources/security-manager/petclinic-adapter.json').find(x=>x.id==='sbom').command;
 try{
  const stub='#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$TRACE"\ncase "$0" in *nice) exit "$GENERATOR_RC";; *) exit "$VERIFIER_RC";; esac\n';
  for(const name of ['nice','node'])fs.writeFileSync(path.join(temp,name),stub,{mode:0o700});
  const trace=path.join(temp,'trace'),r=spawnSync('/bin/sh',['-c',command],{cwd:temp,env:{PATH:temp,TRACE:trace,GENERATOR_RC:String(generatorStatus),VERIFIER_RC:String(verifierStatus)},encoding:'utf8',timeout:5000});return {code:r.status,command,trace:fs.existsSync(trace)?fs.readFileSync(trace,'utf8').trim().split('\n').map(s=>s.replaceAll(temp,'<fixture>')):[]};
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
