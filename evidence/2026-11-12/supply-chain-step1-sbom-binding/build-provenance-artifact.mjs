import fs from 'node:fs';
import {artifactStore} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const raw=p=>fs.readFileSync(new URL('raw/'+p,import.meta.url),'utf8');
const stage=p=>fs.readFileSync('/tmp/sbomstage/'+p,'utf8');
const mavenKeys=bom=>new Set(bom.components.filter(c=>(c.purl||'').startsWith('pkg:maven/')).map(c=>{const m=c.purl.match(/^pkg:maven\/(.+)\/(.+)@([^?]+)/);return m?`${m[1]}:${m[2]}:${m[3]}`:c.purl;}));
const embedded=JSON.parse(raw('embedded-sbom.json'));
const cmp={};
for(const arch of ['amd64','arm64']){
  const t=JSON.parse(stage(`sbom-${arch}.cdx.json`));
  const a=mavenKeys(embedded),b=mavenKeys(t);
  const inter=[...a].filter(x=>b.has(x));
  cmp[arch]={embeddedMavenComponents:a.size,imageMavenComponents:b.size,exactGroupNameVersionMatches:inter.length,
    embeddedOnly:[...a].filter(x=>!b.has(x)).length,imageOnly:[...b].filter(x=>!a.has(x)).length,
    embeddedOnlySample:[...a].filter(x=>!b.has(x)).slice(0,6),imageOnlySample:[...b].filter(x=>!a.has(x)).slice(0,6)};
}
const attAmd=JSON.parse(raw('att-10b60976eaa032fa7e3d1f11366550907a618f76235a210d9fa9222f04a2f879.intoto.json'));
const attArm=JSON.parse(raw('att-ce3beb81951da3bd3bf5420429a440aa42c46e556a4dc7314dd479361f9b4abd.intoto.json'));
const vcsOf=att=>att.predicate.buildDefinition.externalParameters.request.root.request.args;
const assessment={
  schemaVersion:1,kind:'SbomProvenanceAssessment',productionEvidence:false,assessedAt:new Date().toISOString(),
  subject:{registry:'core.harbor.domain',repository:'petclinic/petclinic',
    indexDigest:'sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55',
    amd64ManifestDigest:'sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94',
    arm64ManifestDigest:'sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42'},
  descriptiveBindingBundle:{artifact:'artifact/',sealDigest:'c0b526e11ab3a6b79f9c25475a7ce2e4a3291d2af233d3378e31f3c596cb8ea5',bindingDigest:'71739f4a4033195a64cc41b75bfed8667e4bb3b94be8349f9d1a3e358f47a450'},
  buildProvenance:{
    sourceCommit:'9a78cc89f22fa98fb1ffcc43e2ae279299471793',
    sourceRepository:'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',
    imageBuildJob:{name:'petclinic-candidate-build',number:2,result:'SUCCESS',buildType:'petclinic-maven-buildx-v1',
      startedAt:'2026-10-30T03:14:20.429Z',completedAt:'2026-10-30T03:16:28.097Z',buildMetadataSha256:'2bd5d0251899753f26a42c6d679c16c8e47cb048c3c4a5e742645d506a6babc2'},
    securityGateJob:{name:'petclinic-ci',number:270,result:'SUCCESS',gate:'PASS',mode:'enforce',
      auditTargetImage:'core.harbor.domain/petclinic/petclinic@sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55',
      summarySha256:'ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'},
    harborPushTime:'2026-10-30T03:16:39.550Z',harborTag:'0.10.0-ci-1000002',
    signedStatements:{scheme:'DSSE envelopes verified against infra/security/cosign.pub taken from the source commit itself',
      publicKeySha256:'490c048d85da66076c2c152fdc313930af5e9f309d64a75b3d5be7216dcf50f8',
      buildStatement:'binds commit + builder identity + build number 2 + output index digest',
      securityValidationStatement:'binds commit + build 270 + the exact candidate image'},
    offlineReverification:{script:'evidence/2026-11-05/build-harbor-link/verify.mjs',ranAt:'2026-11-12',exitCode:0,
      environment:'pristine clone of HEAD b36b7554',regeneratedVerifiedJsonByteIdenticalToCommitted:true,
      includedNegativeAssertions:['wrong commit rejected','wrong image digest rejected']},
    platformRecord:'evidence/2026-11-05/build-harbor-link/verified.json (sealed copy in this bundle as build-harbor-link-verified.json)',
    structureNote:'Two explicitly separate historical jobs linked by signed build provenance and #270 exact auditTargetImage; not one image-producing job (platform record wording).',
    harborAttestations:{note:'buildx provenance attestations stored in the index are unsigned copies; the signed originals are the Jenkins-archived DSSE envelopes re-verified above',
      amd64:{manifestDigest:'sha256:10b60976eaa032fa7e3d1f11366550907a618f76235a210d9fa9222f04a2f879',subject:'sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94',vcsRevision:vcsOf(attAmd)['vcs:revision']},
      arm64:{manifestDigest:'sha256:ce3beb81951da3bd3bf5420429a440aa42c46e556a4dc7314dd479361f9b4abd',subject:'sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42',vcsRevision:vcsOf(attArm)['vcs:revision']}},
  },
  applicationArtifact:{
    pathInImage:'/app/app.jar',copiedBy:'Dockerfile COPY target/spring-petclinic-4.0.0-SNAPSHOT.jar app.jar (image config history)',
    sha256:'9e8791f2362cec807f090ae38afbc368950370ef2e21b6a3d9974bc548a07702',bytes:78611896,identicalInBothArchitectures:true,
    layerDigests:{amd64:'sha256:4eeaa64b9ecfd9ae844f814be4b7aa1b2db7326ef9b03c0fb41e5d899f83a296',arm64:'sha256:6212b30165b1bbab959df8161aab84ca0f305eb1062f4436e5ab64d14e73bd99'},
    buildInfo:{artifact:'spring-petclinic',version:'4.0.0-SNAPSHOT',buildTime:'2024-11-28T14:37:52Z'},
    buildTimeExplanation:'build.time equals the pom-pinned project.build.outputTimestamp (reproducible build setting, present at the source commit and at HEAD); the timestamp is a pinned constant, not a wall-clock build record.',
    manifestSbomDeclaration:{sbomLocation:'META-INF/sbom/application.cdx.json',sbomFormat:'CycloneDX'},
  },
  buildTimeSbom:{
    location:'META-INF/sbom/application.cdx.json inside /app/app.jar',file:'embedded-sbom-application.cdx.json',
    sha256:'b0a9ab3d854212e8ff6ace34cfd683775ce32cac955b9d41e038dca78dc2b3f3',bytes:360971,
    specVersion:embedded.specVersion,serialNumber:embedded.serialNumber,subject:embedded.metadata.component.name,
    componentCount:embedded.components.length,
    tool:{name:'cyclonedx-maven-plugin',version:'2.9.3',sha256FromDocument:'c452d5eebe28bc86bef2e7c72d129f04f60877bef843eac8120f01fb655be293',
      matchesPlatformPinnedSbomTool:true},
    scope:'Maven dependency graph of the application artifact only (no OS packages)',
    componentComparisonWithImageContent:cmp,
  },
  relations:[
    {relation:'OCI Index -> child manifests (membership + platform pairing)',verdict:'VERIFIED',evidence:'index bytes sha256 asserted equal to the candidate digest on devops; member set cross-checked against Harbor artifact record in build-harbor-link/verified.json'},
    {relation:'child manifest -> buildx provenance attestation (subject pairing)',verdict:'VERIFIED',evidence:'attestation subjects name the exact child digests with platform parameters; sealed copies in this bundle'},
    {relation:'candidate image -> Jenkins image build + source commit',verdict:'VERIFIED',evidence:'signed DSSE build statement (candidate-build #2, commit 9a78cc89) re-verified offline 2026-11-12, byte-identical regeneration of the platform record'},
    {relation:'candidate image -> security gate build',verdict:'VERIFIED',evidence:'signed security-validation statement + petclinic-ci #270 summary naming the exact index digest as auditTargetImage; re-verified in the same offline run'},
    {relation:'child manifest -> application jar (content)',verdict:'VERIFIED',evidence:'layer extraction on devops; jar sha256 identical in both architectures'},
    {relation:'application jar -> build-time SBOM (co-packaged)',verdict:'VERIFIED',evidence:'SBOM extracted from the jar itself; MANIFEST.MF declares Sbom-Location/Sbom-Format; tool hash equals the platform-pinned CycloneDX Maven plugin 2.9.3'},
    {relation:'build-time SBOM -> image Maven content (descriptive agreement)',verdict:'PARTIAL',evidence:'component-set comparison in buildTimeSbom.componentComparisonWithImageContent: the build-time graph and the filesystem-detected set agree on the bulk of coordinates but differ at the edges (graph-only scopes vs filesystem detection); neither set is a superset claim'},
    {relation:'SBOM generated this round (Trivy, from image content) -> candidate digest',verdict:'VERIFIED_DESCRIPTIVE',evidence:'generated from digest-pinned pulls of the exact child manifests; subject anchored in-document (bom-ref/purl/ImageID); sealed in the descriptive binding bundle. Descriptive inventory binding, not a build record.'},
    {relation:'candidate -> production deployment',verdict:'NOT_DEPLOYED',evidence:'evidence/2026-11-05/candidate-running/verified.json: GitOps/deployment reference a different index (sha256:489cb821...); production Manager NOT_ACTIVE'},
  ],
  overall:{buildProvenance:'VERIFIED',sbomSource:'DUAL (build-time embedded SBOM located and extracted; descriptive image SBOMs generated and sealed this round)',
    remainingGap:'The manager-v2 SBOM plugin formal executor still cannot produce container-image SBOMs (fixed POM fixtures only); the descriptive image SBOMs were produced by a controlled run, not by the plugin pipeline.'},
};
const store=artifactStore(new URL('artifact-provenance/',import.meta.url).pathname);
store.putRaw('embedded-sbom-application.cdx.json',raw('embedded-sbom.json'));
store.putRaw('provenance-attestation-amd64.json',raw('att-10b60976eaa032fa7e3d1f11366550907a618f76235a210d9fa9222f04a2f879.intoto.json'));
store.putRaw('provenance-attestation-arm64.json',raw('att-ce3beb81951da3bd3bf5420429a440aa42c46e556a4dc7314dd479361f9b4abd.intoto.json'));
store.putRaw('build-harbor-link-verified.json',fs.readFileSync(new URL('../../../evidence/2026-11-05/build-harbor-link/verified.json',import.meta.url),'utf8'));
store.put('provenance-assessment.json',assessment);
const fin=store.finish();
console.log(JSON.stringify({provenanceSealDigest:fin.sealDigest,assessmentDigest:digest(assessment),comparison:cmp,files:fin.files},null,2));
