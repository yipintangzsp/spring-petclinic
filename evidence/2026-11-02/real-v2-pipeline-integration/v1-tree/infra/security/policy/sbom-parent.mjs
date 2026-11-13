import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import {sbomEvidence} from './sbom-evidence.mjs';import {sbomObservations,MissingSbomEvidence} from './sbom-observations.mjs';
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
export function sbomParent(raw){
 const lock=JSON.parse(fs.readFileSync(new URL('./versions/sbom-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(lock.sourceHashes))if(sha(fs.readFileSync(new URL('../../../'+p,import.meta.url)))!==h)throw Error('POLICY_ERROR: frozen SBOM source changed');
 if(!raw?.stage||!raw.files||!raw.io)return {decision:null,status:'NOT_CONFIGURED',reason:'Complete SBOM parent facts absent'};
 const f=sbomObservations(raw);let decision='FAIL',report,reason,normalizedFacts={},phase='prerequisite';
 try{
  if(raw.stage==='workflow'){
   if(raw.complete!==true||!raw.execution||!Object.hasOwn(raw.execution,'failed')||!raw.moduleStatus)throw new MissingSbomEvidence('Complete wrapper evidence absent');
   if(raw.execution.failed)decision='FAIL';
   else if(['disabled','skipped'].includes(raw.moduleStatus))return {decision:null,status:'SKIPPED',rawEvidence:structuredClone(raw)};
   else if(raw.moduleStatus==='not_configured')return {decision:null,status:'NOT_CONFIGURED',rawEvidence:structuredClone(raw)};
   else if(raw.moduleStatus==='success')decision='PASS';else if(raw.moduleStatus==='warn')decision='WARN';else decision='FAIL';
   normalizedFacts={moduleStatus:raw.moduleStatus,execution:structuredClone(raw.execution),module:structuredClone(raw.module),observations:structuredClone(raw.observations)};
  }else if(raw.stage==='generic'){
   const runtime=f.need(raw,'runtime');if(runtime.manifestReadError)throw Error(runtime.manifestReadError);const manifest=f.need(runtime,'manifest');JSON.parse(manifest);if(runtime.lockReadError)throw Error(runtime.lockReadError);if(sha(manifest)!==f.need(runtime,'expectedManifestSha256'))throw Error('Locked scanner tool manifest mismatch');
   const c=JSON.parse(f.file('.devsecops/manager-config.json')),source=f.file('.git-sha').trim();
   report={schema:1,tool:'sbom',status:'error',build:Number(c.build),findings:0,blocking:0,project:c.project,source};
   try{
    const lease=f.need(runtime,'lease');f.need(lease,'status');if(lease.error||lease.status!==0)throw Error('Lease query failed');if(JSON.parse(lease.stdout).spec.holderIdentity!==(raw.environment.HEAVY_HOLDER||`jenkins-petclinic-${raw.environment.BUILD_NUMBER}`))throw Error('Existing outer heavy Lease required');
    const full=path.resolve(c.sourceRoot,c.sbomFile);if(!full.startsWith(path.resolve(c.sourceRoot)+'/'))throw Error('Project path outside checkout');
    phase='parse';const bom=JSON.parse(f.file(full));if(bom.bomFormat!=='CycloneDX'||!Array.isArray(bom.components))throw Error('Actual CycloneDX report required');
    f.io('native-write');report.components=bom.components.length;report.reportSha256=sha(JSON.stringify(bom));report.status='success';normalizedFacts={bom:structuredClone(bom),artifactPath:full,components:bom.components.length,scope:'Generic inventory acceptance, no image/digest attestation'};
    decision='PASS';
   }catch(error){if(error instanceof MissingSbomEvidence)throw error;report.error=error.message;reason=error.message;decision='FAIL';}
   finally{f.io('manager-report-write');}
  }else if(['standalone','production'].includes(raw.stage)){
   if(raw.stage==='production'){
    const g=f.need(raw,'generator');f.need(g,'status');normalizedFacts.generator=structuredClone(g);if(g.error||g.status!==0)throw Error('Maven SBOM generation failed');
   }
   phase='extraction';const extraction=f.need(raw,'extraction');f.need(extraction,'status');if(extraction.error||extraction.status!==0)throw Error('JAR SBOM extraction failed');
   const packaged=f.need(extraction,'base64'),maven=f.file('target/classes/META-INF/sbom/application.cdx.json');
   if(!Buffer.from(packaged,'base64').equals(Buffer.from(maven,'base64')))throw Error('Packaged SBOM differs from Maven output');
   f.io('output-mkdir');f.io('sbom-write');phase='validation';
   const validation=sbomEvidence({packagedBase64:packaged,mavenBase64:maven});if(validation.decision!=='PASS')throw Error(validation.reason);
   const bytes=Buffer.from(packaged,'base64'),bom=JSON.parse(bytes);phase='source';const source=f.file('.git-sha').trim();
   report={status:'success',source,createdAt:new Date(f.need(raw,'now')).toISOString(),packagedJarEntry:'META-INF/sbom/application.cdx.json',format:bom.bomFormat,specVersion:bom.specVersion,components:bom.components.length,dependencyNodes:bom.dependencies.length,sha256:sha(bytes),scope:'Maven production dependencies; not OS packages, scanner or all platform images'};
   normalizedFacts={...normalizedFacts,format:bom.bomFormat,specVersion:bom.specVersion,components:bom.components.length,dependencyNodes:bom.dependencies.length,inventory:structuredClone(bom),artifactSha256:report.sha256,source,scope:report.scope};phase='report-write';f.io('summary-write');decision='PASS';
  }else throw Error('Unsupported SBOM stage');
 }catch(error){reason=error.message;decision=error instanceof MissingSbomEvidence?null:'FAIL';}
 return {decision,status:decision??'NOT_TESTED',reason,failurePhase:decision==='FAIL'?phase:null,report,normalizedFacts,trace:f.trace,rawEvidence:structuredClone(raw)};
}
