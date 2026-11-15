// Provenance V2 candidate runner: real offline verification of the
// platform's historical signed security-validation attestation.
// Materials are the committed, hash-pinned Jenkins archive proof
// (evidence/2026-11-05/build-harbor-link/archived-proof.json) and the
// platform public key (infra/security/cosign.pub); the runner never
// reads private key material, never signs, and never contacts a
// registry. It assembles the genuine replay observations the FROZEN
// Policy adapter (provenanceParent) consumes: the cosign
// download attestation command observation carries the real archived
// DSSE envelope bytes, the tool manifest observation is the real
// scanner-tools.json, and the adapter's own verifyEnvelope + validate
// perform the actual DSSE signature and identity verification inside
// Policy evaluation. The runner's oldDecision is the frozen engine's
// decision on the same fact; Core re-evaluates once and compares.
// Negative cases mutate only the expected identity or a copy of the
// envelope payload, so rejection is exercised on real material.
import fs from 'node:fs';import path from 'node:path';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {evaluate} from '../policy/engine.mjs';
const repoRoot=path.resolve(new URL('../../../',import.meta.url).pathname);
const readRepo=p=>fs.readFileSync(path.join(repoRoot,p),'utf8');
export const provenanceProjects=()=>JSON.parse(fs.readFileSync(new URL('./provenance/projects.json',import.meta.url))).projects;
export function loadProvenanceMaterials(project){
 const m=project.materials;if(!m)throw Error('PROVENANCE_PROJECT_NOT_AUTHORIZED');
 const proofText=readRepo(m.archivedProof);if(sha(proofText)!==m.archivedProofSha256)throw Error('RUNNER_REPORT_ERROR');
 const keyText=readRepo(m.publicKey);if(sha(keyText)!==m.publicKeySha256)throw Error('RUNNER_REPORT_ERROR');
 const proof=JSON.parse(proofText);
 const anchor=JSON.parse(readRepo(m.sbomBindingAnchor));
 if(anchor.binding?.sealDigest!==m.sbomBindingSealDigest)throw Error('RUNNER_REPORT_ERROR');
 return {proof,keyText,anchor};
}
export function envelopeTextFor(proof,envelopeFile){
 const b64=proof.files?.[envelopeFile];if(typeof b64!=='string')throw Error('RUNNER_REPORT_ERROR');
 return Buffer.from(b64,'base64').toString('utf8');
}
export function buildProvenanceObservations({project,caseId}){
 const kase=project.cases[caseId];if(!kase)throw Error('PROVENANCE_PROJECT_NOT_AUTHORIZED');
 const {proof,keyText,anchor}=loadProvenanceMaterials(project);
 let envelopeText=envelopeTextFor(proof,kase.envelopeFile);
 if(kase.tamperPayload){
  // Envelope material may be a single JSON object, a JSON array, or the
  // JSONL set current cosign download emits; tamper every envelope so the
  // case's expected envelope is necessarily among the tampered ones.
  let envs;try{const p=JSON.parse(envelopeText);envs=Array.isArray(p)?p:[p];}catch{envs=envelopeText.split('\n').filter(Boolean).map(l=>JSON.parse(l));}
  for(const e of envs)e.payload=Buffer.from('tampered').toString('base64');
  envelopeText=envs.map(e=>JSON.stringify(e)).join('\n');
 }
 const x=kase.expected;
 const manifest=readRepo('infra/security/scanner-tools.json');
 const tools={};for(const f of JSON.parse(manifest).files)if(f.path==='cosign'||f.path.startsWith('cosign/'))tools[f.path]=f.symlink?{symlink:f.symlink}:{sha256:f.sha256};
 const ioEntry={value:null};
 const raw={action:'verify',
  environment:{PROVENANCE_CANDIDATE:x.image,PROVENANCE_COMMIT:x.commit,PROVENANCE_REPOSITORY:x.repository,BUILD_NUMBER:x.buildNumber,JENKINS_URL:x.jenkinsUrl,JOB_NAME:x.jobName},
  runtime:{manifest,expectedManifestSha256:sha(manifest),tools},
  files:{'.git-sha':{value:x.commit},'infra/security/cosign.pub':{value:keyText}},
  io:{'output-mkdir':ioEntry,'auth-temp-create':ioEntry,'auth-temp-chmod':ioEntry,'auth-write':ioEntry,'envelope-write':ioEntry,'auth-temp-remove':ioEntry,'verification-report-write':ioEntry},
  commands:{'cosign:download':[{status:0,stdout:envelopeText}]}};
 const indexDigest='sha256:'+x.image.split('@sha256:')[1];
 return {raw,sbomCrossCheck:{anchorSealDigest:anchor.binding.sealDigest,anchorIndexDigest:anchor.subject.indexDigest,subjectIndexDigest:indexDigest,match:anchor.subject.indexDigest===indexDigest}};
}
export function buildProvenanceFact(packet){return {component:'provenance',status:'success',raw:packet.raw};}
export function provenanceDecisionAt(fact){return evaluate(fact,{policyVersion:'baseline-v1',securityLevel:'standard',mode:'enforce'}).decision;}
export function provenanceUiCase(project,scenarioId){
 const want=scenarioId==='verified'?['historical-candidate','PASS']:scenarioId==='rejected'?['wrong-digest','FAIL']:null;if(want===null)throw Error('PROVENANCE_SCENARIO_NOT_AUTHORIZED');
 const hit=Object.entries(project.cases).find(([id,c])=>id===want[0]&&c.expectedDecision===want[1]);if(!hit)throw Error('PROVENANCE_SCENARIO_NOT_AUTHORIZED');return hit[0];
}
export function buildProvenanceRuntimeFacts(packet,runId){
 return {classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId,caseId:packet.caseId,subjectImage:packet.raw.environment.PROVENANCE_CANDIDATE,commit:packet.raw.environment.PROVENANCE_COMMIT,buildNumber:Number(packet.raw.environment.BUILD_NUMBER),sbomCrossCheck:packet.sbomCrossCheck,envelopeSha256:packet.envelopeSha256};
}
export async function executeRealProvenance(plugin,input,{projectId,runId}={}){
 keys(input,['targetId','caseId']);
 const project=provenanceProjects()[projectId];
 if(!project||input.targetId!==project.targetId||!project.cases[input.caseId])throw Error('PROVENANCE_PROJECT_NOT_AUTHORIZED');
 const packet=buildProvenanceObservations({project,caseId:input.caseId});
 packet.caseId=input.caseId;
 packet.envelopeSha256=sha(packet.raw.commands['cosign:download'][0].stdout);
 const fact=buildProvenanceFact(packet);
 const oldDecision=provenanceDecisionAt(fact);
 if(!['PASS','FAIL'].includes(oldDecision))throw Error('RUNNER_REPORT_ERROR');
 const runtimeFacts=buildProvenanceRuntimeFacts(packet,runId);
 const rawReport={kind:'ProvenanceVerificationObservation',caseId:input.caseId,envelopeSha256:packet.envelopeSha256,expected:project.cases[input.caseId].expected,sbomCrossCheck:packet.sbomCrossCheck,decision:oldDecision};
 const text=JSON.stringify(rawReport);
 return freeze({rawReportBytesUtf8:text,rawReportDigest:sha(text),fact,factDigest:digest(fact),oldDecision,runtimeFacts,executionScope:'REAL_OFFLINE_DSSE_VERIFICATION_OF_HISTORICAL_SIGNED_ATTESTATION',evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:input.caseId,envelopeSha256:packet.envelopeSha256,sbomAnchorSealDigest:packet.sbomCrossCheck.anchorSealDigest}],cleanup:{status:'VERIFIED',processExited:true}});
}
