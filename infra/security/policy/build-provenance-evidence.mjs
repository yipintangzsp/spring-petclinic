import fs from 'node:fs';import crypto from 'node:crypto';
// Consume verification/execution observations from the unchanged build verifier.
// No source file hashing, build, DSSE verification or BuildKit inference occurs here.
export function buildProvenanceEvidence(raw){
 const version=JSON.parse(fs.readFileSync(new URL('./versions/build-provenance-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(version.sourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen Build Provenance source changed');
 const absent=reason=>({decision:null,status:'NOT_TESTED',reason,rawEvidence:structuredClone(raw)});
 if(!raw||raw.schema!==1||raw.source!=='build-provenance-verification'||raw.policyVersion!=='baseline-v1')return absent('Versioned Build Provenance facts absent');
 if(raw.complete!==true||!raw.execution||!Object.hasOwn(raw.execution,'exitCode')||!Array.isArray(raw.observations)||!raw.artifacts)return absent('Incomplete execution/verification evidence');
 if(!['package','image','harbor-copy','create','verify'].includes(raw.phase)){
  if(raw.execution.exitCode===0)return absent('Unsupported stage cannot be accepted');
 }
 if(!raw.inputIdentity)return absent('Bound input identity absent');
 const code=raw.execution.exitCode;
 if(!Number.isInteger(code))return absent('Actual verifier exit status unavailable');
 // Error taxonomy/diagnostics and original reports are facts, never remapped into CVE severity.
 if(code===0){
  const reports={package:'.devsecops/build-compilation.json',image:'.devsecops/build-provenance.json','harbor-copy':'target/platform/harbor-copy.json',create:'.devsecops/build-attestation-verification.json',verify:'.devsecops/build-attestation-verification.json'};
  if(!Object.hasOwn(raw.artifacts,reports[raw.phase]))return absent('Successful verifier report unavailable');
  if(['create','verify'].includes(raw.phase)&&!Object.hasOwn(raw.artifacts,'.devsecops/build-attestation-envelope.json'))return absent('Verified attestation envelope unavailable');
 }
 const decision=code===0?'PASS':'FAIL';
 return {decision,status:decision,normalizedFacts:{phase:raw.phase,execution:structuredClone(raw.execution),artifacts:structuredClone(raw.artifacts),observations:structuredClone(raw.observations),inputIdentity:structuredClone(raw.inputIdentity)},rawEvidence:structuredClone(raw)};
}
