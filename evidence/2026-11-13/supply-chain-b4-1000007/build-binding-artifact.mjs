import fs from 'node:fs';
import {artifactStore} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const STAGE='/tmp/sbomstage-b4';
const facts=fs.readFileSync(STAGE+'/facts.txt','utf8');
const kv={};for(const line of facts.split('\n')){const m=line.match(/^(\w+)=(.*)$/);if(m)kv[m[1]]=m[2];}
const archLine=a=>{const line=facts.split('\n').find(l=>l.startsWith(a+' '));const o={};for(const tok of line.split(' ').slice(1)){const i=tok.indexOf('=');o[tok.slice(0,i)]=tok.slice(i+1);}return o;};
const INDEX='sha256:a8e800ef6a66081eebbd2a620f24f42c16b36dc33860bdf83d934e63a9ffb072';
const images=[];
for(const arch of ['amd64','arm64']){
  const f=archLine(arch);
  const text=fs.readFileSync(`${STAGE}/sbom-${arch}.cdx.json`,'utf8');
  const bom=JSON.parse(text);
  const comp=bom.metadata.component;
  const props=Object.fromEntries((comp.properties||[]).filter(p=>p.name==='aquasecurity:trivy:ImageID').map(p=>[p.name,p.value]));
  const purls={};for(const c of bom.components){const m=(c.purl||'').match(/^pkg:([^/]+)\//);if(m)purls[m[1]]=(purls[m[1]]||0)+1;}
  const os=bom.components.find(c=>c.type==='operating-system');
  images.push({arch,f,text,bom,comp,props,purls,os});
}
const receipt={
  schemaVersion:1,kind:'SbomGenerationReceipt',classification:'REAL_CONTROLLED_EXECUTION',
  executionHost:'devops (192.168.1.58)',identity:{user:'security-trivy',uid:990,gid:983},
  workDirectory:'/var/lib/security-trivy/data/b4-20261113',
  tool:{name:'trivy',version:kv.toolVersion,sha256:kv.toolSha256,pinnedSha256MatchesRegistry:true,
    invocation:'trivy image --insecure --format cyclonedx --output <file> --cache-dir /var/lib/security-trivy/db-cache --skip-db-update --skip-java-db-update core.harbor.domain/petclinic/petclinic@<child-manifest-digest> (run from the controlled work directory)'},
  registryAuth:'project robot (pull-only) from /var/lib/security-trivy/credentials.json; values not recorded',
  inputAssertions:{indexDigest:INDEX,indexBytesSha256Verified:true,manifestBytesSha256Verified:['amd64','arm64']},
  cacheSeed:'platform db-cache refreshed 2026-11-13 from official GHCR artifacts (trivy-db:2 manifest sha256:9d570840823a4fbd0004ccdd251e89dd59d91aa093df55bc541d493eca406ad0, layer sha256:fd406c50cad6892a16b258bef67be31ebfd4ddfb00da80ce869b461e73116d4f; trivy-java-db:1 layer sha256:d1ef50b7b265c67362f7d61a22d7dcc507346b1252e2173d046edd5ddcb26fd6), downloaded via the verified Mac route, installed root:security-trivy mode 440; db UpdatedAt 2026-11-13T07:00:07Z, java-db UpdatedAt 2026-11-13T01:08:15Z; no DB download performed by the scanner',
  attempts:[
    {n:1,result:'FAILED',reason:'trivy auto-loaded a trivy.yaml from the process CWD that the security-trivy identity cannot read (config file loading error, permission denied); launcher amended to cd into the controlled work directory before invoking trivy'},
    {n:2,result:'COMPLETED',reason:'both architectures generated, exit code 0; the dual-arch vulnerability rescans in the same controlled setup also exited 0'}],
  runs:images.map(({arch,f})=>({platform:'linux/'+arch,manifestDigest:f.manifestDigest,configDigest:f.configDigest,layerCount:Number(f.layers),startedAt:f.startedAt,completedAt:f.completedAt,exitCode:0,sbomSha256:f.sbomSha256,sbomBytes:Number(f.sbomBytes)})),
};
const binding={
  schemaVersion:1,kind:'SbomDigestBinding',productionEvidence:false,
  createdAt:new Date().toISOString(),
  round:'B4 re-anchor for candidate build #7 (tag 0.10.0-ci-1000007), superseding the step-1/step-2 binding subject index sha256:2fbaea65...',
  path:{mode:'CONTROLLED_RUN',formalPluginPath:'UNAVAILABLE_FOR_CONTAINER_IMAGE',
    formalPathEvidence:'manager-v2 sbom-real executor generates only from fixed POM fixtures (scope APPLICATION_MAVEN_DEPENDENCIES_ONLY); its README states the fixture SBOM does not attest the Harbor candidate. Additionally the platform SBOM Policy accepts CycloneDX 1.6 only while generated image SBOMs are CycloneDX 1.7 (open decision item U6; Policy not changed by this round). This binding was produced by a controlled run and sealed with the platform artifactStore + summary-v2 codec digest, the same sealing mechanism as candidate runs.',
    sealing:'CandidateArtifactSeal (infra/security/manager-v2/result.mjs artifactStore)'},
  subject:{registry:'core.harbor.domain',repository:'petclinic/petclinic',indexDigest:INDEX,indexMediaType:'application/vnd.oci.image.index.v1+json'},
  indexMembers:[
    {digest:'sha256:5bed9d1ddeae0a136577d55e72cf6cfe9f57d55d0390cdc15c8a98bc50c02169',role:'IMAGE_MANIFEST',platform:'linux/amd64',sbomCovered:true},
    {digest:'sha256:3cc885b3cbe2709ef7aaf384382477a33d996cfd4125d4489e7d3446793c6e57',role:'IMAGE_MANIFEST',platform:'linux/arm64',sbomCovered:true},
    {digest:'sha256:6ea75d0b576264699009b2f81b5cd400eb4e0c384bdad640bb6c80f9c260ba7f',role:'ATTESTATION_MANIFEST',platform:'unknown/unknown',sbomCovered:false,reason:'single in-toto layer (build provenance document), not an image filesystem',subject:'sha256:5bed9d1ddeae0a136577d55e72cf6cfe9f57d55d0390cdc15c8a98bc50c02169'},
    {digest:'sha256:541bdddbfa68d4aa5494b50a0471a23d4b173bfb197c7c5adcf20c82aa6d1c2b',role:'ATTESTATION_MANIFEST',platform:'unknown/unknown',sbomCovered:false,reason:'single in-toto layer (build provenance document), not an image filesystem',subject:'sha256:3cc885b3cbe2709ef7aaf384382477a33d996cfd4125d4489e7d3446793c6e57'}],
  images:images.map(({arch,f,bom,comp,props,purls,os})=>({
    platform:'linux/'+arch,manifestDigest:f.manifestDigest,configDigest:f.configDigest,layerCount:Number(f.layers),
    sbomFile:`sbom-image-${arch}.cdx.json`,sbomSha256:f.sbomSha256,sbomBytes:Number(f.sbomBytes),
    sbomFormat:bom.bomFormat,sbomSpecVersion:bom.specVersion,sbomSerialNumber:bom.serialNumber,
    subjectBomRef:comp['bom-ref'],subjectName:comp.name,subjectImageId:props['aquasecurity:trivy:ImageID'],
    toolRecordedInDocument:{name:bom.metadata.tools.components[0].name,version:bom.metadata.tools.components[0].version},
    componentCount:bom.components.length,dependencyEntries:bom.dependencies.length,
    componentKinds:purls,operatingSystem:{name:os.name,version:os.version}})),
  tool:{name:'trivy',version:kv.toolVersion,sha256:kv.toolSha256,outputFormat:'CycloneDX',outputSpecVersion:images[0].bom.specVersion},
  vulnerabilityRescan:{
    mode:'CONTROLLED_RUN (same identity, tool and refreshed DB cache as this SBOM generation)',
    acceptance:{highZeroBothArchitectures:true,targetCveAbsent:'CVE-2026-109518'},
    amd64:{reportFile:'raw/scan-amd64.json',reportSha256:'eb68772865c3102360279d4baa169a9eb9ba15a01cd8552abb0ae517dc3b0a80',counts:{CRITICAL:0,HIGH:0,MEDIUM:82,LOW:4},fixedPackages:{'apt':'3.2.1ubuntu0.1','libapt-pkg7.0':'3.2.1ubuntu0.1'}},
    arm64:{reportFile:'raw/scan-arm64.json',reportSha256:'93c9eb555560206ccf1ea9aa6a0492b4bb9995ca2a0302a76438e1030aba21b7',counts:{CRITICAL:0,HIGH:0,MEDIUM:82,LOW:4},fixedPackages:{'apt':'3.2.1ubuntu0.1','libapt-pkg7.0':'3.2.1ubuntu0.1'}},
    note:'MEDIUM count (82) is higher than the previous candidate scan (58) because the vulnerability DB was refreshed to 2026-11-13 before this rescan; the acceptance criteria (HIGH=0 on both architectures, CVE-2026-109518 absent, fixed package versions present) are met.'},
  coverage:{
    includes:['Ubuntu 26.04 OS package inventory (pkg:deb components) detected in the image filesystems','Java libraries (pkg:maven components) detected in the image filesystems','the operating-system component itself','CycloneDX dependency graph'],
    excludes:['the two attestation manifests of the index (in-toto provenance documents, not image filesystems)','content not recognized by Trivy 0.76.2 filesystem analyzers (payloads without package metadata)','runtime configuration, environment variables and data volumes','vulnerability assessment - an SBOM is an inventory, not a scan result (the companion rescan is recorded under vulnerabilityRescan)']},
  sourceMaterial:'SBOMs were generated from the candidate image content itself: registry pull by pinned child-manifest digest and layer filesystem analysis on devops. The image was not rebuilt in this step and no Jenkins build was triggered by the SBOM step.',
  generationReceiptFile:'sbom-generation-receipt.json',
};
const here=new URL('.',import.meta.url).pathname;
const store=artifactStore(here+'artifact');
for(const {arch,text} of images)store.putRaw(`sbom-image-${arch}.cdx.json`,text);
store.put('sbom-generation-receipt.json',receipt);
store.put('sbom-binding.json',binding);
const fin=store.finish();
console.log(JSON.stringify({sealDigest:fin.sealDigest,bindingDigest:digest(binding),receiptDigest:digest(receipt),files:fin.files},null,2));
