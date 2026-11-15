// Build Provenance V2 candidate runner: real offline verification of
// the platform's historical signed image-build attestation.
// The runner itself executes the platform's existing DSSE verifier
// (verifyEnvelope) and build-statement validator
// (validateBuildStatement) over the committed, hash-pinned Jenkins
// archive proof, using only the platform public key. It never signs,
// never reads private key material and never contacts a registry.
// The outcome is shaped as the versioned verification facts the
// FROZEN Policy adapter (buildProvenanceEvidence) consumes: exitCode
// 0 only when signature and full build identity (subject digest,
// source commit/repository, builder identity and build number,
// jar/buildkit anchors, platform set, chronology) all verify.
// Negative cases mutate only the expected identity or a copy of the
// envelope payload, so rejection is exercised on real material.
// The verified subject digest is additionally cross-checked against
// the supply-chain step1 SBOM binding seal anchor.
import fs from 'node:fs';import path from 'node:path';
import {sha,digest,freeze} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {evaluate} from '../policy/engine.mjs';
import {verifyEnvelope} from '../provenance/contract.mjs';
import {validateBuildStatement} from '../provenance/build-contract.mjs';
const repoRoot=path.resolve(new URL('../../../',import.meta.url).pathname);
const readRepo=p=>fs.readFileSync(path.join(repoRoot,p),'utf8');
export const buildProvenanceProjects=()=>JSON.parse(fs.readFileSync(new URL('./build-provenance/projects.json',import.meta.url))).projects;
export function verifyBuildEnvelope({project,caseId}){
 const kase=project.cases[caseId];if(!kase)throw Error('BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED');
 const m=project.materials;if(!m)throw Error('BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED');
 const proofText=readRepo(m.archivedProof);if(sha(proofText)!==m.archivedProofSha256)throw Error('RUNNER_REPORT_ERROR');
 const keyText=readRepo(m.publicKey);if(sha(keyText)!==m.publicKeySha256)throw Error('RUNNER_REPORT_ERROR');
 const anchor=JSON.parse(readRepo(m.sbomBindingAnchor));
 if(anchor.binding?.sealDigest!==m.sbomBindingSealDigest)throw Error('RUNNER_REPORT_ERROR');
 const proof=JSON.parse(proofText);
 const b64=proof.files?.[kase.envelopeFile];if(typeof b64!=='string')throw Error('RUNNER_REPORT_ERROR');
 let envelopeText=Buffer.from(b64,'base64').toString('utf8');
 let envelopes;try{const parsed=JSON.parse(envelopeText);envelopes=Array.isArray(parsed)?parsed:[parsed];}catch{try{envelopes=envelopeText.split('\n').filter(Boolean).map(l=>JSON.parse(l));}catch{throw Error('RUNNER_REPORT_ERROR');}}
 if(kase.tamperPayload){envelopes=envelopes.map(e=>({...e,payload:Buffer.from('tampered').toString('base64')}));envelopeText=JSON.stringify(envelopes);}
 const expected=kase.expected;
 const observations=[];let exitCode=0,diagnostic=null,statement=null;
 try{
  const statements=envelopes.map(e=>verifyEnvelope(e,keyText));
  observations.push({type:'existing-dsse-verifier',verified:true,envelopes:statements.length});
  statement=statements.find(st=>{try{validateBuildStatement(st,expected);return true;}catch{return false;}});
  if(!statement)throw Error('Build identity mismatch');
  validateBuildStatement(statement,expected);
  observations.push({type:'existing-build-validator',valid:true});
 }catch(e){exitCode=1;diagnostic=e.message;observations.push({type:'existing-build-validator',valid:false,diagnostic});}
 const indexDigest='sha256:'+expected.image.split('@sha256:')[1];
 const sbomCrossCheck={anchorSealDigest:anchor.binding.sealDigest,anchorIndexDigest:anchor.subject.indexDigest,subjectIndexDigest:indexDigest,match:exitCode===0&&anchor.subject.indexDigest===indexDigest};
 observations.push({type:'sbom-anchor-crosscheck',...sbomCrossCheck});
 const report={tool:'build-provenance',status:exitCode===0?'success':'failed',phase:'verify',expected,diagnostic,sbomCrossCheck};
 const raw={schema:1,source:'build-provenance-verification',policyVersion:'baseline-v1',complete:true,phase:'verify',
  execution:{exitCode,...(diagnostic?{diagnostic}:{})},observations,
  artifacts:{'.devsecops/build-attestation-verification.json':report,'.devsecops/build-attestation-envelope.json':envelopes},
  inputIdentity:{projectId:null,requestedVerification:{image:expected.image,commit:expected.commit,repository:expected.repository,builder:expected.builder,buildNumber:expected.buildNumber}}};
 return {raw,statement,exitCode,sbomCrossCheck,envelopeSha256:sha(envelopeText)};
}
export function buildBuildProvenanceFact(packet){return {component:'build-provenance',status:'success',raw:packet.raw};}
export function buildProvenanceDecisionAt(fact){return evaluate(fact,{policyVersion:'baseline-v1',securityLevel:'standard',mode:'enforce'}).decision;}
export function buildProvenanceUiCase(project,scenarioId){
 const want=scenarioId==='verified'?['historical-build','PASS']:scenarioId==='rejected'?['wrong-digest','FAIL']:null;if(want===null)throw Error('BUILD_PROVENANCE_SCENARIO_NOT_AUTHORIZED');
 const hit=Object.entries(project.cases).find(([id,c])=>id===want[0]&&c.expectedDecision===want[1]);if(!hit)throw Error('BUILD_PROVENANCE_SCENARIO_NOT_AUTHORIZED');return hit[0];
}
export async function executeRealBuildProvenance(plugin,input,{projectId,runId}={}){
 keys(input,['targetId','caseId']);
 const project=buildProvenanceProjects()[projectId];
 if(!project||input.targetId!==project.targetId||!project.cases[input.caseId])throw Error('BUILD_PROVENANCE_PROJECT_NOT_AUTHORIZED');
 const packet=verifyBuildEnvelope({project,caseId:input.caseId});
 packet.raw.inputIdentity.projectId=projectId;
 const fact=buildBuildProvenanceFact(packet);
 const oldDecision=buildProvenanceDecisionAt(fact);
 if(oldDecision!==(packet.exitCode===0?'PASS':'FAIL'))throw Error('RUNNER_REPORT_ERROR');
 const runtimeFacts={classification:'REAL_CONTROLLED_EXECUTION',validationRunId:runId,caseId:input.caseId,exitCode:packet.exitCode,subjectImage:project.cases[input.caseId].expected.image,commit:packet.statement?.predicate?.source?.commit??null,buildNumber:packet.statement?.predicate?.builder?.buildNumber??null,jarSha256:packet.statement?.predicate?.compilation?.jarSha256??null,sbomCrossCheck:packet.sbomCrossCheck,envelopeSha256:packet.envelopeSha256};
 const rawReport={kind:'BuildProvenanceVerificationObservation',caseId:input.caseId,exitCode:packet.exitCode,expected:project.cases[input.caseId].expected,sbomCrossCheck:packet.sbomCrossCheck,decision:oldDecision};
 const text=JSON.stringify(rawReport);
 return freeze({rawReportBytesUtf8:text,rawReportDigest:sha(text),fact,factDigest:digest(fact),oldDecision,runtimeFacts,executionScope:'REAL_OFFLINE_DSSE_VERIFICATION_OF_HISTORICAL_SIGNED_BUILD_ATTESTATION',evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',runId,validationRunId:runId,caseId:input.caseId,envelopeSha256:packet.envelopeSha256,sbomAnchorSealDigest:packet.sbomCrossCheck.anchorSealDigest}],cleanup:{status:'VERIFIED',processExited:true}});
}
