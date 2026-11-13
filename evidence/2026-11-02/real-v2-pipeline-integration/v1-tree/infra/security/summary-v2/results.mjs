import {EXPECTED_SOURCES} from './inventory.mjs';
import {digest,equal,fail,freeze,object,validateBinding} from './codec.mjs';

const fields = ['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides','status','decision'];
const statuses = ['PASS','WARN','FAIL','ERROR','SKIPPED','DISABLED','NOT_CONFIGURED','NOT_TESTED'];
const hash = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
export function validateMetadata(result) {
  if (!object(result) || !equal(Object.keys(result).sort(),[...fields].sort())) fail('malformed resolved metadata');
  if (result.policyVersion !== 'baseline-v1' || !['low','standard','strict'].includes(result.securityLevel)) fail('resolved policy identity');
  if (typeof result.profile !== 'string' || !result.profile || !object(result.effectivePolicy) || !Array.isArray(result.appliedOverrides)) fail('resolved policy metadata');
  if (!EXPECTED_SOURCES.every(id => object(result.effectivePolicy[id]))) fail('incomplete effectivePolicy');
  for (const policy of Object.values(result.effectivePolicy)) {
    if (!object(policy) || !equal(Object.keys(policy).sort(),['Critical','High','Medium','Low','Info'].sort()) || !Object.values(policy).every(v => ['PASS','WARN','FAIL'].includes(v))) fail('malformed effectivePolicy');
  }
  for (const override of result.appliedOverrides) {
    if (!object(override) || !['profile','component','project'].includes(override.layer) || !object(override.values)) fail('malformed override evidence');
    if (override.layer !== 'profile' && !Object.hasOwn(result.effectivePolicy,override.component)) fail('unknown override component');
    if (override.layer === 'profile' && override.profile !== result.profile) fail('override profile mismatch');
    if (Object.entries(override.values).some(([k,v]) => !['Critical','High','Medium','Low','Info'].includes(k) || !['PASS','WARN','FAIL'].includes(v))) fail('override values');
  }
  if (!statuses.includes(result.status) || ![null,'PASS','WARN','FAIL'].includes(result.decision)) fail('resolved decision');
  if (['SKIPPED','DISABLED','NOT_CONFIGURED','NOT_TESTED'].includes(result.status) ? result.decision !== null : result.decision !== (result.status === 'ERROR' ? 'FAIL' : result.status)) fail('status/decision mismatch');
  return result;
}
export function validateResult(value,binding) {
  const keys = ['schema','kind','sourceId','component','scope','binding','rawFactDigest','configDigest','result','error','evidenceComplete','resultDigest'];
  if (!object(value) || !equal(Object.keys(value).sort(),keys.sort()) || value.schema !== 1 || value.kind !== 'ResolvedPolicyResult') fail('malformed source result');
  if (!EXPECTED_SOURCES.includes(value.sourceId) || value.sourceId !== value.component || value.scope !== 'pre-approval') fail('wrong source identity');
  validateBinding(value.binding);
  if (!equal(value.binding,binding)) fail('stale source binding');
  if (!hash(value.rawFactDigest) || !hash(value.configDigest) || typeof value.evidenceComplete !== 'boolean') fail('source digest/evidence');
  const {resultDigest,...payload} = value;
  if (!hash(resultDigest) || digest(payload) !== resultDigest) fail('source result integrity');
  if (value.error !== null) {
    if (value.result !== null || !equal(Object.keys(value.error).sort(),['code','message']) || value.error.code !== 'POLICY_ERROR' || !value.error.message?.startsWith('POLICY_ERROR:')) fail('invalid POLICY_ERROR receipt');
  } else validateMetadata(value.result);
  return freeze(structuredClone(value));
}

// Gate/Summary/Promotion project this same receipt; none may supply an evaluator.
export function gateView(resolved,binding) {
  const r = validateResult(resolved,binding);
  return freeze({sourceId:r.sourceId,resultDigest:r.resultDigest,status:r.error?'POLICY_ERROR':r.result.status,decision:r.error?null:r.result.decision});
}
