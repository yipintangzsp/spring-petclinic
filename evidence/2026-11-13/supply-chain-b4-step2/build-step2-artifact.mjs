import fs from 'node:fs';
import {artifactStore} from '../../../infra/security/manager-v2/result.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const S='/tmp/b4step2stage/sign', D='/tmp/b4step2stage/docs';
const here=new URL('.',import.meta.url).pathname;
const chain=JSON.parse(fs.readFileSync(D+'/provenance-chain.json','utf8'));
const decision=JSON.parse(fs.readFileSync(D+'/release-decision.json','utf8'));
const sigRec={schemaVersion:1,kind:'CandidateSignatureRecord',...chain.candidateSignatures,
  documentSignatures:[
   {document:'provenance-chain.json',sha256:sha(fs.readFileSync(D+'/provenance-chain.json')),signatureSha256:sha(fs.readFileSync(D+'/provenance-chain.sig'))},
   {document:'release-decision.json',sha256:sha(fs.readFileSync(D+'/release-decision.json')),signatureSha256:sha(fs.readFileSync(D+'/release-decision.sig'))}]};
const kyvRec={schemaVersion:1,kind:'KyvernoAdmissionRecord',...chain.kyvernoAdmission};
const store=artifactStore(here+'artifact');
store.putRaw('provenance-chain.json',fs.readFileSync(D+'/provenance-chain.json','utf8'));
store.putRaw('release-decision.json',fs.readFileSync(D+'/release-decision.json','utf8'));
const sigObj=(obj,digest,p)=>({schemaVersion:1,kind:'CosignBlobSignature',object:obj,digest,signatureBase64:fs.readFileSync(p,'utf8').trim(),signatureSha256:sha(fs.readFileSync(p))});
store.put('signature-provenance-chain.json',sigObj('PROVENANCE_CHAIN_DOCUMENT',null,D+'/provenance-chain.sig'));
store.put('signature-release-decision.json',sigObj('RELEASE_DECISION_DOCUMENT',null,D+'/release-decision.sig'));
store.put('signature-index.json',sigObj('OCI_INDEX',chain.subject.indexDigest,S+'/sigs/index.sig'));
store.put('signature-manifest-amd64.json',sigObj('IMAGE_MANIFEST',chain.subject.children.amd64,S+'/sigs/manifest-amd64.sig'));
store.put('signature-manifest-arm64.json',sigObj('IMAGE_MANIFEST',chain.subject.children.arm64,S+'/sigs/manifest-arm64.sig'));
store.put('candidate-signatures.json',sigRec);
store.put('kyverno-admission.json',kyvRec);
const fin=store.finish();
const anchor={subject:{repository:'petclinic/petclinic',indexDigest:chain.subject.indexDigest},
 step2:{artifactDir:'artifact',sealDigest:fin.sealDigest,chainDigest:digest(chain),decisionDigest:digest(decision),signatureRecordDigest:digest(sigRec),kyvernoRecordDigest:digest(kyvRec)},
 step1:{bindingSealDigest:chain.sbomBinding.bindingSealDigest,provenanceSealDigest:chain.sbomBinding.provenanceSealDigest}};
fs.writeFileSync(here+'binding-anchor.json',JSON.stringify(anchor,null,2));
console.log(JSON.stringify({sealDigest:fin.sealDigest,chainDigest:anchor.step2.chainDigest,decisionDigest:anchor.step2.decisionDigest,files:fin.files},null,2));
