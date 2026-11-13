import {evaluateAsync} from '../policy/engine.mjs';
import {EXPECTED_SOURCES} from './inventory.mjs';
import {canonical,digest,fail,freeze,validateBinding} from './codec.mjs';
import {validateResult,validateMetadata} from './results.mjs';

// The only candidate module importing/evaluating the existing Policy Engine.
// Claim BEFORE await: duplicate/concurrent/retried evaluations are rejected.
// Deliberately not wired into Jenkins until complete observation capture exists.
export function createSourceOwner(binding) {
  validateBinding(binding);
  const bound = freeze(structuredClone(binding)),claimed = new Set(),results = new Map(),counts = {};
  return Object.freeze({
    async evaluateOnce(sourceId,facts,config = {}) {
      if (!EXPECTED_SOURCES.includes(sourceId) || facts?.component !== sourceId) fail('wrong canonical source');
      if (claimed.has(sourceId)) fail('duplicate source evaluation: '+sourceId);
      claimed.add(sourceId); counts[sourceId] = 0;
      const snapshot = structuredClone(facts),configuration = structuredClone(config);
      const rawFactDigest = digest(snapshot),configDigest = digest(configuration);
      let result = null,error = null;
      try {
        counts[sourceId]++;
        const evaluated = await evaluateAsync(snapshot,configuration);
        result = Object.fromEntries(['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides','status','decision'].map(k => [k,structuredClone(evaluated[k])]));
        validateMetadata(result);
      } catch (caught) {
        // Do not persist exception messages potentially containing secret data.
        if (!String(caught.message).startsWith('POLICY_ERROR:')) throw caught;
        error = {code:'POLICY_ERROR',message:'POLICY_ERROR: source evaluation rejected; inspect protected execution diagnostics'};
        result = null;
      }
      if (digest(snapshot) !== rawFactDigest || canonical(facts) !== canonical(snapshot)) fail('raw facts mutated during evaluation');
      const payload = {schema:1,kind:'ResolvedPolicyResult',sourceId,component:sourceId,scope:'pre-approval',binding:bound,
        rawFactDigest,configDigest,result,error,
        evidenceComplete:result?.status !== 'NOT_TESTED' && !(facts.status === 'success' && result?.status === 'NOT_CONFIGURED')};
      const resolved = validateResult({...payload,resultDigest:digest(payload)},bound);
      results.set(sourceId,resolved); return resolved;
    },
    get(sourceId) { if (!results.has(sourceId)) fail('source evaluation not finalized'); return results.get(sourceId); },
    counts() { return freeze({...counts}); }
  });
}
