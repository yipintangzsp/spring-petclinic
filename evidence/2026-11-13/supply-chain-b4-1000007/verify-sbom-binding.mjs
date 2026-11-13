// Offline independent verification of the B4 SBOM -> candidate digest binding.
// Usage: node verify-sbom-binding.mjs
// Exit 0 only if every positive check passes and every negative case is rejected.
import fs from 'node:fs';
import os from 'node:os';
import {verifyArtifact} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const here=new URL('.',import.meta.url).pathname;
const anchor=JSON.parse(fs.readFileSync(here+'binding-anchor.json','utf8'));
const readJson=p=>JSON.parse(fs.readFileSync(p,'utf8'));
let pass=0,fail=0;
const ok=(id,cond,detail='')=>{console.log(`${cond?'PASS':'FAIL'} ${id}${detail?' '+detail:''}`);cond?pass++:fail++;};
const mustReject=(id,fn)=>{try{fn();ok(id,false,'(was accepted)');}catch(e){ok(id,true,`(${String(e.message||e).slice(0,80)})`);}};
const artifactDir=here+anchor.binding.artifactDir;
const provDir=here+anchor.provenance.artifactDir;
const binding=readJson(artifactDir+'/sbom-binding.json');
const COMMIT='318d479fb458ff229d0e10ed99ae7317f7427625';
// ---- positive: seals and digests ----
ok('P1_BINDING_SEAL',verifyArtifact(artifactDir,anchor.binding.sealDigest)===true);
ok('P2_BINDING_DIGEST',digest(binding)===anchor.binding.bindingDigest);
ok('P3_RECEIPT_DIGEST',digest(readJson(artifactDir+'/sbom-generation-receipt.json'))===anchor.binding.receiptDigest);
ok('P4_PROVENANCE_SEAL',verifyArtifact(provDir,anchor.provenance.sealDigest)===true);
const assessment=readJson(provDir+'/provenance-assessment.json');
ok('P5_ASSESSMENT_DIGEST',digest(assessment)===anchor.provenance.assessmentDigest);
ok('P6_BUNDLES_CROSS_LINKED',assessment.descriptiveBindingBundle.sealDigest===anchor.binding.sealDigest);
// ---- positive: per-arch subject binding ----
const assertSubject=(doc,entry)=>{
  const comp=doc.metadata?.component||{};
  if(!String(comp['bom-ref']||'').includes(entry.manifestDigest))throw new Error('subject bom-ref does not name the manifest digest');
  const img=(comp.properties||[]).find(p=>p.name==='aquasecurity:trivy:ImageID');
  if(!img||img.value!==entry.configDigest)throw new Error('ImageID != config digest');
  if(doc.serialNumber!==entry.sbomSerialNumber)throw new Error('serialNumber mismatch');
};
for(const entry of binding.images){
  const bytes=fs.readFileSync(artifactDir+'/'+entry.sbomFile);
  ok('P7_SBOM_SHA_'+entry.platform,sha(bytes.toString('utf8'))===entry.sbomSha256);
  try{assertSubject(JSON.parse(bytes.toString('utf8')),entry);ok('P8_SUBJECT_'+entry.platform,true);}catch(e){ok('P8_SUBJECT_'+entry.platform,false,String(e.message));}
}
// ---- positive: index membership ----
const assertIndex=(indexBytes,expectedIndexDigest,members)=>{
  if('sha256:'+sha(indexBytes.toString('utf8'))!==expectedIndexDigest)throw new Error('index digest mismatch');
  const idx=JSON.parse(indexBytes.toString('utf8'));
  const got=new Set(idx.manifests.map(m=>'sha256:'+m.digest.split(':')[1]));
  const want=new Set(members.map(m=>m.digest));
  if(got.size!==want.size||[...want].some(d=>!got.has(d)))throw new Error('index member set mismatch');
  for(const m of idx.manifests){const rec=members.find(x=>x.digest==='sha256:'+m.digest.split(':')[1]);if(!rec)throw new Error('unrecorded member');if(rec.role==='IMAGE_MANIFEST'&&m.platform&&(m.platform.os+'/'+m.platform.architecture)!==rec.platform)throw new Error('platform pairing mismatch');}
};
try{assertIndex(fs.readFileSync(here+'raw/index.json'),anchor.subject.indexDigest,binding.indexMembers);ok('P9_INDEX_MEMBERSHIP',true);}catch(e){ok('P9_INDEX_MEMBERSHIP',false,String(e.message));}
// ---- positive: embedded build-time SBOM + attestations inside provenance bundle ----
const embeddedBytes=fs.readFileSync(provDir+'/embedded-sbom-application.cdx.json').toString('utf8');
ok('P10_EMBEDDED_SBOM_SHA',sha(embeddedBytes)===assessment.buildTimeSbom.sha256);
for(const arch of ['amd64','arm64']){
  const att=readJson(provDir+`/provenance-attestation-${arch}.json`);
  const entry=binding.images.find(i=>i.platform==='linux/'+arch);
  ok('P11_ATTESTATION_SUBJECT_'+arch,att.subject?.[0]?.digest?.sha256===entry.manifestDigest.replace('sha256:',''));
  const vcs=att.predicate?.buildDefinition?.externalParameters?.request?.root?.request?.args?.['vcs:revision'];
  ok('P12_ATTESTATION_VCS_'+arch,vcs===COMMIT);
}
// ---- positive: rescan reports recomputed ----
for(const arch of ['amd64','arm64']){
  const d=readJson(here+`raw/scan-${arch}.json`);
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};let cve=false;const pkgs={};
  for(const r of d.Results||[]){
    for(const v of r.Vulnerabilities||[]){counts[v.Severity]=(counts[v.Severity]||0)+1;if(v.VulnerabilityID==='CVE-2026-109518')cve=true;}
    for(const p of r.Packages||[]){if(p.Name==='apt'||p.Name==='libapt-pkg7.0')pkgs[p.Name]=p.Version;}
  }
  const rec=assessment.buildProvenance.securityGate.results[arch];
  const countsMatch=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].every(k=>(counts[k]||0)===(rec.counts[k]||0));
  ok('P13_RESCAN_'+arch,counts.HIGH===0&&counts.CRITICAL===0&&!cve&&pkgs.apt==='3.2.1ubuntu0.1'&&pkgs['libapt-pkg7.0']==='3.2.1ubuntu0.1'&&countsMatch);
}
// ---- negatives (every one must be rejected) ----
const tmp=fs.mkdtempSync(os.tmpdir()+'/sbomverify-b4-');
const copyDir=(src,name)=>{const d=tmp+'/'+name;fs.cpSync(src,d,{recursive:true});for(const f of fs.readdirSync(d))fs.chmodSync(d+'/'+f,0o600);return d;};
// N1: one flipped byte in the arm64 SBOM copy
{
  const d=copyDir(artifactDir,'n1');const p=d+'/sbom-image-arm64.cdx.json';const b=fs.readFileSync(p);b[5000]=b[5000]^0x01;fs.writeFileSync(p,b);
  mustReject('N1_TAMPERED_SBOM_REJECTED',()=>verifyArtifact(d,anchor.binding.sealDigest));
}
// N2: wrong expected index digest (all-zero)
mustReject('N2_WRONG_INDEX_DIGEST_REJECTED',()=>assertIndex(fs.readFileSync(here+'raw/index.json'),'sha256:'+'0'.repeat(64),binding.indexMembers));
// N3a: arch swap - arm64 SBOM presented for the amd64 manifest
{
  const armDoc=readJson(artifactDir+'/sbom-image-arm64.cdx.json');
  const amdEntry=binding.images.find(i=>i.platform==='linux/amd64');
  mustReject('N3A_ARCH_SWAP_REJECTED',()=>assertSubject(armDoc,amdEntry));
}
// N3b: index digest presented as if it were a child manifest digest
{
  const armDoc=readJson(artifactDir+'/sbom-image-arm64.cdx.json');
  const armEntry=binding.images.find(i=>i.platform==='linux/arm64');
  mustReject('N3B_INDEX_AS_CHILD_REJECTED',()=>assertSubject(armDoc,{...armEntry,manifestDigest:anchor.subject.indexDigest}));
}
// N4: tampered binding record inside a copy
{
  const d=copyDir(artifactDir,'n4');const p=d+'/sbom-binding.json';const b=fs.readFileSync(p);b[120]=b[120]^0x01;fs.writeFileSync(p,b);
  mustReject('N4_TAMPERED_BINDING_REJECTED',()=>verifyArtifact(d,anchor.binding.sealDigest));
}
// N5: cross-project SBOM (java-sbom-demo-b fixture SBOM) presented for this candidate
{
  const bBytes=fs.readFileSync(new URL('../../../evidence/2026-11-06/sbom-second-project/generated-b.cdx.json',import.meta.url),'utf8');
  const armEntry=binding.images.find(i=>i.platform==='linux/arm64');
  ok('N5A_CROSS_PROJECT_SHA_DIFFERS',sha(bBytes)!==armEntry.sbomSha256);
  mustReject('N5B_CROSS_PROJECT_SUBJECT_REJECTED',()=>assertSubject(JSON.parse(bBytes),armEntry));
  mustReject('N5C_CROSS_BUNDLE_ANCHOR_REJECTED',()=>verifyArtifact(artifactDir,anchor.provenance.sealDigest));
}
// N6: index copy with one child digest altered
{
  const idx=readJson(here+'raw/index.json');idx.manifests[0].digest='sha256:'+'1'.repeat(64);
  mustReject('N6_INDEX_MEMBER_TAMPER_REJECTED',()=>assertIndex(Buffer.from(JSON.stringify(idx)),anchor.subject.indexDigest,binding.indexMembers)&&assertIndex(fs.readFileSync(here+'raw/index.json'),anchor.subject.indexDigest,binding.indexMembers.map(m=>m.digest===idx.manifests[0].digest?{...m}:m)));
}
// N7: cross-candidate - previous candidate (build #2) arm64 SBOM presented for this candidate
{
  const oldBytes=fs.readFileSync(new URL('../../../evidence/2026-11-12/supply-chain-step1-sbom-binding/artifact/sbom-image-arm64.cdx.json',import.meta.url),'utf8');
  const armEntry=binding.images.find(i=>i.platform==='linux/arm64');
  ok('N7A_CROSS_CANDIDATE_SHA_DIFFERS',sha(oldBytes)!==armEntry.sbomSha256);
  mustReject('N7B_CROSS_CANDIDATE_SUBJECT_REJECTED',()=>assertSubject(JSON.parse(oldBytes),armEntry));
}
console.log(`RESULT pass=${pass} fail=${fail}`);
process.exit(fail?1:0);
