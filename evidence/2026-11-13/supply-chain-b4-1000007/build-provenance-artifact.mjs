import fs from 'node:fs';
import crypto from 'node:crypto';
import {artifactStore} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const raw=p=>fs.readFileSync(new URL('raw/'+p,import.meta.url),'utf8');
const stage=p=>fs.readFileSync('/tmp/sbomstage-b4/'+p,'utf8');
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
const attAmd=JSON.parse(raw('att-6ea75d0b5762.intoto.json'));
const attArm=JSON.parse(raw('att-541bdddbfa68.intoto.json'));
const vcsOf=att=>att.predicate.buildDefinition.externalParameters.request.root.request.args;
// recompute the rescan facts from the sealed raw reports (no transcription)
const rescan={};
for(const arch of ['amd64','arm64']){
  const bytes=raw(`scan-${arch}.json`);const d=JSON.parse(bytes);
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};let cve=false;const pkgs={};
  for(const r of d.Results||[]){
    for(const v of r.Vulnerabilities||[]){counts[v.Severity]=(counts[v.Severity]||0)+1;if(v.VulnerabilityID==='CVE-2026-109518')cve=true;}
    for(const p of r.Packages||[]){if(p.Name==='apt'||p.Name==='libapt-pkg7.0')pkgs[p.Name]=p.Version;}
  }
  rescan[arch]={reportSha256:crypto.createHash('sha256').update(bytes).digest('hex'),counts,targetCvePresent:cve,fixedPackages:pkgs};
}
const COMMIT='318d479fb458ff229d0e10ed99ae7317f7427625';
const assessment={
  schemaVersion:1,kind:'SbomProvenanceAssessment',productionEvidence:false,assessedAt:new Date().toISOString(),
  round:'B4 re-anchor for candidate build #7 (tag 0.10.0-ci-1000007)',
  subject:{registry:'core.harbor.domain',repository:'petclinic/petclinic',
    indexDigest:'sha256:a8e800ef6a66081eebbd2a620f24f42c16b36dc33860bdf83d934e63a9ffb072',
    amd64ManifestDigest:'sha256:5bed9d1ddeae0a136577d55e72cf6cfe9f57d55d0390cdc15c8a98bc50c02169',
    arm64ManifestDigest:'sha256:3cc885b3cbe2709ef7aaf384382477a33d996cfd4125d4489e7d3446793c6e57'},
  descriptiveBindingBundle:{artifact:'artifact/',sealDigest:'ce3c1ff04941a7041e70125ae6ce8f92caaf4ac0146678cc4c033dcbf06323e1',bindingDigest:'b1985adc74186372c551b734823fcaf6e09c2bd321891e78d27fba9e246a1c1f'},
  buildProvenance:{
    sourceCommit:COMMIT,
    sourceRepository:'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',
    fixDescription:'infra/runtime/openssl-packages.json only: pins apt + libapt-pkg7.0 to 3.2.1ubuntu0.1 (CVE-2026-109518) for both architectures; branch fix/u2-apt-cve-2026-109518',
    imageBuildJob:{name:'petclinic-candidate-build',number:7,result:'SUCCESS',
      startedAt:'2026-11-13T07:46:22.697Z',durationMs:344809,
      evidence:'controller build.xml on the Jenkins PVC read on devops 2026-11-13: <result>SUCCESS</result>, SCM revision field equals the fix commit; the job is pinned-commit style and was pinned to 318d479f for builds #4-#7'},
    securityGate:{mode:'CONTROLLED_RESCAN',tool:'trivy 0.76.2 (platform-pinned binary, sha256 7844c3851b28470b6d7f0975fa0b3262c5b2272c9a54a91f522801bb8926f51f)',
      identity:'security-trivy (uid 990), project pull robot read-only',
      db:'platform db-cache refreshed 2026-11-13 from official GHCR artifacts via the verified Mac route (db UpdatedAt 2026-11-13T07:00:07Z; java-db UpdatedAt 2026-11-13T01:08:15Z)',
      note:'petclinic-ci has NOT run on this candidate and no DSSE security-validation statement exists for it; the gate evidence for this round is this controlled dual-arch rescan, sealed with this bundle set (full reports in raw/)',
      results:rescan,
      acceptance:'HIGH=0 and CRITICAL=0 on both architectures; CVE-2026-109518 absent on both; apt and libapt-pkg7.0 detected at the fixed version 3.2.1ubuntu0.1 on both'},
    harborTag:'0.10.0-ci-1000007',
    harborPresence:'build pushed the candidate to the local registry (127.0.0.1:13050); presence in Harbor verified 2026-11-13 by read-only manifest GET returning the exact index digest; tag listed among 89 tags of petclinic/petclinic',
    signedStatements:{scheme:'NONE for this build',
      note:'build #7 produced no DSSE envelopes (the previous candidate had them only because separate statement jobs ran for build #2 / petclinic-ci #270). Provenance for this candidate rests on the Jenkins build record plus the buildx SLSA provenance attestations carried in the index; those attestation copies are unsigned, the same caveat recorded for the previous candidate.'},
    harborAttestations:{note:'buildx provenance attestations stored in the index (unsigned copies)',
      amd64:{manifestDigest:'sha256:6ea75d0b576264699009b2f81b5cd400eb4e0c384bdad640bb6c80f9c260ba7f',subject:'sha256:5bed9d1ddeae0a136577d55e72cf6cfe9f57d55d0390cdc15c8a98bc50c02169',vcsRevision:vcsOf(attAmd)['vcs:revision']},
      arm64:{manifestDigest:'sha256:541bdddbfa68d4aa5494b50a0471a23d4b173bfb197c7c5adcf20c82aa6d1c2b',subject:'sha256:3cc885b3cbe2709ef7aaf384382477a33d996cfd4125d4489e7d3446793c6e57',vcsRevision:vcsOf(attArm)['vcs:revision']}},
  },
  applicationArtifact:{
    pathInImage:'/app/app.jar',copiedBy:'Dockerfile COPY target/spring-petclinic-4.0.0-SNAPSHOT.jar app.jar (image config history)',
    sha256:'be01f8ce2db70b3a5f4f8dcff9fe185a59cccbfe402ee0ac8ad378ab01dca401',bytes:78612070,identicalInBothArchitectures:true,
    layerDigests:{amd64:'sha256:d302635127743210420fd4750c2b5502d9410f2234132ab19abba1715a95f2bf',arm64:'sha256:31c20df8508ce8bd66f7e9be99f036c35f9de93dc96ec7548cee35b1e4d7ac55'},
    buildInfo:{artifact:'spring-petclinic',version:'4.0.0-SNAPSHOT'},
    buildTimeExplanation:'build.time in this project is the pom-pinned project.build.outputTimestamp (reproducible build setting); it is a pinned constant, not a wall-clock build record, and is not used as provenance evidence here.',
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
    note:'byte-identical to the previous candidate embedded SBOM (same sha256), consistent with a fix that changed only OS package pins, not application dependencies',
    componentComparisonWithImageContent:cmp,
  },
  relations:[
    {relation:'OCI Index -> child manifests (membership + platform pairing)',verdict:'VERIFIED',evidence:'index bytes fetched from Harbor on devops, sha256 asserted equal to the candidate index digest; member set recorded in the binding record and re-checked by the independent verifier'},
    {relation:'child manifest -> buildx provenance attestation (subject pairing)',verdict:'VERIFIED',evidence:'attestation subjects name the exact child digests with platform parameters; sealed copies in this bundle'},
    {relation:'candidate image -> Jenkins image build + source commit',verdict:'VERIFIED',evidence:'Jenkins build #7 build.xml (SUCCESS; SCM revision = fix commit 318d479f) plus both attestation vcs:revision fields equal to the same commit (asserted by the independent verifier). Attestations are unsigned buildx copies; no DSSE envelope exists for this build.'},
    {relation:'candidate image -> security gate',verdict:'VERIFIED_CONTROLLED',evidence:'controlled dual-arch Trivy rescan (refreshed DB): HIGH=0/CRITICAL=0 both architectures, CVE-2026-109518 absent, fixed package versions detected; full reports sealed in raw/ and summarised in buildProvenance.securityGate.results. No petclinic-ci run or signed gate statement exists for this candidate.'},
    {relation:'child manifest -> application jar (content)',verdict:'VERIFIED',evidence:'jar layer extracted from Harbor blobs for BOTH architectures on devops; jar sha256 identical in both architectures'},
    {relation:'application jar -> build-time SBOM (co-packaged)',verdict:'VERIFIED',evidence:'SBOM extracted from the jar itself; MANIFEST.MF declares Sbom-Location/Sbom-Format; tool hash equals the platform-pinned CycloneDX Maven plugin 2.9.3; bytes identical to the previous candidate'},
    {relation:'build-time SBOM -> image Maven content (descriptive agreement)',verdict:'PARTIAL',evidence:'component-set comparison in buildTimeSbom.componentComparisonWithImageContent: the build-time graph and the filesystem-detected set agree on the bulk of coordinates but differ at the edges (graph-only scopes vs filesystem detection); neither set is a superset claim'},
    {relation:'SBOM generated this round (Trivy, from image content) -> candidate digest',verdict:'VERIFIED_DESCRIPTIVE',evidence:'generated from digest-pinned pulls of the exact child manifests; subject anchored in-document (bom-ref/purl/ImageID); sealed in the descriptive binding bundle. Descriptive inventory binding, not a build record.'},
    {relation:'candidate -> production deployment',verdict:'NOT_DEPLOYED',evidence:'this round made no production change (final sweep: Manager NOT_ACTIVE, Argo production untouched, production petclinic undisturbed); the candidate is not deployed'},
  ],
  overall:{buildProvenance:'VERIFIED',sbomSource:'DUAL (build-time embedded SBOM located and extracted; descriptive image SBOMs generated and sealed this round)',
    remainingGap:'The manager-v2 SBOM plugin formal executor still cannot produce container-image SBOMs (fixed POM fixtures only) and the SBOM Policy accepts CycloneDX 1.6 only while generated SBOMs are 1.7 (open decision item U6); the descriptive image SBOMs were produced by a controlled run, not by the plugin pipeline.'},
};
const store=artifactStore(new URL('artifact-provenance/',import.meta.url).pathname);
store.putRaw('embedded-sbom-application.cdx.json',raw('embedded-sbom.json'));
store.putRaw('provenance-attestation-amd64.json',raw('att-6ea75d0b5762.intoto.json'));
store.putRaw('provenance-attestation-arm64.json',raw('att-541bdddbfa68.intoto.json'));
store.put('rescan-summary.json',{schemaVersion:1,kind:'B4ControlledRescanSummary',subject:assessment.subject,tool:'trivy 0.76.2',results:rescan,acceptance:assessment.buildProvenance.securityGate.acceptance});
store.put('provenance-assessment.json',assessment);
const fin=store.finish();
console.log(JSON.stringify({provenanceSealDigest:fin.sealDigest,assessmentDigest:digest(assessment),comparison:cmp,files:fin.files},null,2));
