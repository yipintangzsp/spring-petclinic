import {checkCosignVerification} from '../cosign-verification.mjs';
import {validatePriorExit,validateRuntimeContinuity} from '../runtime/health-contract.mjs';
import {persistentRuntime} from '../runtime/event-policy.mjs';
import {verifyEnvelope,validate} from '../provenance/contract.mjs';
import {validateBuildStatement} from '../provenance/build-contract.mjs';
import {validateGate,approvedRelease} from '../promotion/contract.mjs';
const contracts={
 'cosign-cli':raw=>{checkCosignVerification(raw.kind,raw.exitStatus,raw.stderr);},
 'falco-prior-exit':raw=>validatePriorExit(raw.current)?.warning?'WARN':'PASS',
 'falco-continuity':raw=>{validateRuntimeContinuity(raw.current,raw.baseline);},
 'falco-persistence':raw=>persistentRuntime(raw.first,raw.second).blocking.length?'FAIL':'PASS',
 'provenance-signature':raw=>{validate(verifyEnvelope(raw.envelope,raw.publicKey),raw.expected);},
 'build-provenance-signature':raw=>{validateBuildStatement(verifyEnvelope(raw.envelope,raw.publicKey),raw.expected);},
 'approval-evidence':raw=>{validateGate(raw.gate);},
 'approval-signatures':raw=>{approvedRelease(raw.gate,raw.signing);}
};
// These are explicitly scoped evidence contracts, not complete scanner/operational stages.
export const frozenContracts=Object.keys(contracts);
export function frozenContractEvidence(component,raw){
 if(!contracts[component])throw Error('POLICY_ERROR: unknown frozen contract');
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw Error('POLICY_ERROR: frozen evidence object required');
 const rawEvidence=structuredClone(raw);
 try{return {component,rawEvidence,decision:contracts[component](raw)??'PASS',contractScope:component};}
 catch(error){return {component,rawEvidence,decision:'FAIL',reason:error.message,contractScope:component};}
}
