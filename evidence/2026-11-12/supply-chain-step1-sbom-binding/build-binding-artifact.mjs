import fs from 'node:fs';
import {artifactStore} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const STAGE='/tmp/sbomstage';
const facts=fs.readFileSync(STAGE+'/facts.txt','utf8');
const kv={};for(const line of facts.split('\n')){const m=line.match(/^(\w+)=(.*)$/);if(m)kv[m[1]]=m[2];}
const archLine=a=>{const line=facts.split('\n').find(l=>l.startsWith(a+' '));const o={};for(const tok of line.split(' ').slice(1)){const i=tok.indexOf('=');o[tok.slice(0,i)]=tok.slice(i+1);}return o;};
const INDEX='sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55';
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
  workDirectory:'/var/lib/security-trivy/data/sbom-step1-20261112',
  tool:{name:'trivy',version:kv.toolVersion,sha256:kv.toolSha256,pinnedSha256MatchesRegistry:true,
    invocation:'trivy image --insecure --format cyclonedx --output <file> --cache-dir <work>/cache --skip-db-update --skip-java-db-update --timeout 10m core.harbor.domain/petclinic/petclinic@<child-manifest-digest>'},
  registryAuth:'project robot (pull-only) from /var/lib/security-trivy/credentials.json; values not recorded',
  inputAssertions:{indexDigest:INDEX,indexBytesSha256Verified:true,manifestBytesSha256Verified:['amd64','arm64']},
  cacheSeed:'private cache seeded with a copy of the platform db-cache refreshed 2026-11-12 (db + java-db + fanal); no DB download performed',
  attempts:[
    {n:1,result:'FAILED',reason:'TLS x509 unknown authority against internal self-signed Harbor; --insecure added (content integrity anchored by digest assertions)'},
    {n:2,result:'FAILED',reason:'Java DB cannot be skipped on first run with an empty private cache; platform db-cache copy used as seed'},
    {n:3,result:'COMPLETED',reason:'both architectures generated, exit code 0'}],
  runs:images.map(({arch,f})=>({platform:'linux/'+arch,manifestDigest:f.manifestDigest,configDigest:f.configDigest,layerCount:Number(f.layers),startedAt:f.startedAt,completedAt:f.completedAt,exitCode:0,sbomSha256:f.sbomSha256,sbomBytes:Number(f.sbomBytes)})),
};
const binding={
  schemaVersion:1,kind:'SbomDigestBinding',productionEvidence:false,
  createdAt:new Date().toISOString(),
  path:{mode:'CONTROLLED_RUN',formalPluginPath:'UNAVAILABLE_FOR_CONTAINER_IMAGE',
    formalPathEvidence:'manager-v2 sbom-real executor generates only from fixed POM fixtures (scope APPLICATION_MAVEN_DEPENDENCIES_ONLY); sbom/README.md states it is "not a full container-image SBOM" and "The fixture SBOM does not attest the previous Harbor candidate: its link stays UNVERIFIED". No image executor exists in manager-v2; this binding was produced by a controlled run and sealed with the platform artifactStore + summary-v2 codec digest, the same sealing mechanism as candidate runs.',
    sealing:'CandidateArtifactSeal (infra/security/manager-v2/result.mjs artifactStore)'},
  subject:{registry:'core.harbor.domain',repository:'petclinic/petclinic',indexDigest:INDEX,indexMediaType:'application/vnd.oci.image.index.v1+json'},
  indexMembers:[
    {digest:'sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94',role:'IMAGE_MANIFEST',platform:'linux/amd64',sbomCovered:true},
    {digest:'sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42',role:'IMAGE_MANIFEST',platform:'linux/arm64',sbomCovered:true},
    {digest:'sha256:10b60976eaa032fa7e3d1f11366550907a618f76235a210d9fa9222f04a2f879',role:'ATTESTATION_MANIFEST',platform:'unknown/unknown',sbomCovered:false,reason:'single in-toto layer (build provenance document), not an image filesystem'},
    {digest:'sha256:ce3beb81951da3bd3bf5420429a440aa42c46e556a4dc7314dd479361f9b4abd',role:'ATTESTATION_MANIFEST',platform:'unknown/unknown',sbomCovered:false,reason:'single in-toto layer (build provenance document), not an image filesystem'}],
  images:images.map(({arch,f,bom,comp,props,purls,os})=>({
    platform:'linux/'+arch,manifestDigest:f.manifestDigest,configDigest:f.configDigest,layerCount:Number(f.layers),
    sbomFile:`sbom-image-${arch}.cdx.json`,sbomSha256:f.sbomSha256,sbomBytes:Number(f.sbomBytes),
    sbomFormat:bom.bomFormat,sbomSpecVersion:bom.specVersion,sbomSerialNumber:bom.serialNumber,
    subjectBomRef:comp['bom-ref'],subjectName:comp.name,subjectImageId:props['aquasecurity:trivy:ImageID'],
    toolRecordedInDocument:{name:bom.metadata.tools.components[0].name,version:bom.metadata.tools.components[0].version},
    componentCount:bom.components.length,dependencyEntries:bom.dependencies.length,
    componentKinds:purls,operatingSystem:{name:os.name,version:os.version}})),
  tool:{name:'trivy',version:kv.toolVersion,sha256:kv.toolSha256,outputFormat:'CycloneDX',outputSpecVersion:images[0].bom.specVersion},
  coverage:{
    includes:['Ubuntu 26.04 OS package inventory (pkg:deb components) detected in the image filesystems','Java libraries (pkg:maven components) detected in the image filesystems','the operating-system component itself','CycloneDX dependency graph'],
    excludes:['the two attestation manifests of the index (in-toto provenance documents, not image filesystems)','content not recognized by Trivy 0.76.2 filesystem analyzers (payloads without package metadata)','runtime configuration, environment variables and data volumes','vulnerability assessment - an SBOM is an inventory, not a scan result']},
  sourceMaterial:'SBOMs were generated from the candidate image content itself: registry pull by pinned child-manifest digest and layer filesystem analysis on devops. The image was not rebuilt and no Jenkins build was triggered.',
  generationReceiptFile:'sbom-generation-receipt.json',
};
const here=new URL('.',import.meta.url).pathname;
const store=artifactStore(here+'artifact');
for(const {arch,text} of images)store.putRaw(`sbom-image-${arch}.cdx.json`,text);
store.put('sbom-generation-receipt.json',receipt);
store.put('sbom-binding.json',binding);
const fin=store.finish();
console.log(JSON.stringify({sealDigest:fin.sealDigest,bindingDigest:digest(binding),receiptDigest:digest(receipt),files:fin.files},null,2));
