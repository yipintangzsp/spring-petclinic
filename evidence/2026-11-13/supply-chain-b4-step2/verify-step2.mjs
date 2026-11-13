// Offline independent verification of the B4 step-2 evidence (cosign / kyverno / release approval).
// Usage: node verify-step2.mjs   (exit 0 only if all positives pass and all negatives are rejected)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {verifyArtifact} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const here=new URL('.',import.meta.url).pathname;
const anchor=JSON.parse(fs.readFileSync(here+'binding-anchor.json','utf8'));
const A=here+anchor.step2.artifactDir;
const readJson=p=>JSON.parse(fs.readFileSync(p,'utf8'));
let pass=0,fail=0;
const ok=(id,cond,detail='')=>{console.log(`${cond?'PASS':'FAIL'} ${id}${detail?' '+detail:''}`);cond?pass++:fail++;};
const pub=fs.readFileSync(new URL('../../../infra/security/cosign.pub',import.meta.url),'utf8');
const ecdsaOk=(data,sigB64)=>{try{const v=crypto.createVerify('SHA256');v.update(data);return v.verify({key:pub,dsaEncoding:'der'},Buffer.from(String(sigB64).trim(),'base64'));}catch{return false;}};
// positives: seal + digests
ok('P1_SEAL',verifyArtifact(A,anchor.step2.sealDigest)===true);
const chain=readJson(A+'/provenance-chain.json'),decision=readJson(A+'/release-decision.json');
ok('P2_CHAIN_DIGEST',digest(chain)===anchor.step2.chainDigest);
ok('P3_DECISION_DIGEST',digest(decision)===anchor.step2.decisionDigest);
ok('P4_DECISION_LINKS_CHAIN',decision.provenanceChain.sha256===sha(fs.readFileSync(A+'/provenance-chain.json')));
ok('P5_DECISION_APPROVED',decision.status==='APPROVED'&&decision.candidateDigest===anchor.subject.indexDigest&&/NOT a deployment/.test(decision.decisionScope)&&Array.isArray(decision.blockers)&&decision.blockers.length===0);
// positives: ECDSA signatures (pure node, no cosign binary needed)
const sigOf=f=>readJson(A+'/'+f).signatureBase64;
ok('P6_SIG_CHAIN_DOC',ecdsaOk(fs.readFileSync(A+'/provenance-chain.json'),sigOf('signature-provenance-chain.json')));
ok('P7_SIG_DECISION_DOC',ecdsaOk(fs.readFileSync(A+'/release-decision.json'),sigOf('signature-release-decision.json')));
const pairs=[['index','signature-index.json'],['manifest-amd64','signature-manifest-amd64.json'],['manifest-arm64','signature-manifest-arm64.json']];
for(const [name,sig] of pairs){
  const bytes=fs.readFileSync(here+'raw/'+name+'.json');
  ok('P8_SIG_'+name,ecdsaOk(bytes,sigOf(sig)));
  ok('P9_BYTES_DIGEST_'+name,'sha256:'+sha(bytes)===chain.subject.indexDigest||Object.values(chain.subject.children).includes('sha256:'+sha(bytes)));
}
// positives: step1 (this round's SBOM bundle) cross-link
const step1=readJson(new URL('../supply-chain-b4-1000007/binding-anchor.json',import.meta.url).pathname);
ok('P10_STEP1_LINK',chain.sbomBinding.bindingSealDigest===step1.binding.sealDigest&&chain.sbomBinding.provenanceSealDigest===step1.provenance.sealDigest);
// positives: internal consistency of the recorded admission outcome + supersession pointer
const cand=chain.kyvernoAdmission.cases.find(c=>c.case==='candidate-index');
ok('P11_KYVERNO_CANDIDATE_ALLOWED',!!cand&&/^ALLOWED/.test(cand.dryRunServer)&&/CREATED/.test(cand.realCreate||''));
ok('P12_SUPERSEDES_OLD',decision.supersedes&&decision.supersedes.candidateDigest==='sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55');
// negatives
const tampered=Buffer.from(fs.readFileSync(here+'raw/index.json'));tampered[tampered.length-2]^=1;
ok('N1_TAMPERED_INDEX_REJECTED',!ecdsaOk(tampered,sigOf('signature-index.json')));
ok('N2_ARCH_SWAP_REJECTED',!ecdsaOk(fs.readFileSync(here+'raw/manifest-amd64.json'),sigOf('signature-manifest-arm64.json')));
ok('N3_DOC_TAMPER_REJECTED',!ecdsaOk(Buffer.from(JSON.stringify({...chain,createdAt:'x'})),sigOf('signature-provenance-chain.json')));
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'b4step2-verify-'));
try{fs.cpSync(A,tmp+'/artifact',{recursive:true});const f=tmp+'/artifact/provenance-chain.json';fs.chmodSync(f,0o600);const b=fs.readFileSync(f);b[10]^=1;fs.writeFileSync(f,b);
  let rejected=false;try{rejected=verifyArtifact(tmp+'/artifact',anchor.step2.sealDigest)!==true;}catch{rejected=true;}
  ok('N4_SEAL_TAMPER_REJECTED',rejected);
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
console.log(`RESULT pass=${pass} fail=${fail}`);
process.exit(fail?1:0);
