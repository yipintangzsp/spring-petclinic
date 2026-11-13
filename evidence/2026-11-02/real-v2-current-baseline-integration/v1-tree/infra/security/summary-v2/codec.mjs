import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

export const fail = message => { throw Error('POLICY_ERROR: '+message); };
export const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
export const equal = isDeepStrictEqual;
export function canonical(value) {
  const visit = x => {
    if (x === null || typeof x === 'boolean' || typeof x === 'string') return x;
    if (typeof x === 'number' && Number.isFinite(x)) return x;
    if (Array.isArray(x)) return x.map(visit);
    if (!object(x) || ![Object.prototype,null].includes(Object.getPrototypeOf(x))) fail('non-JSON value');
    return Object.fromEntries(Object.keys(x).sort().map(k => [k,visit(x[k])]));
  };
  return JSON.stringify(visit(value));
}
export const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const digest = x => sha(canonical(x));
export function freeze(x) {
  if (object(x) || Array.isArray(x)) { Object.values(x).forEach(freeze); Object.freeze(x); }
  return x;
}
export function validateBinding(binding) {
  const keys = ['job','build','project','source','candidate','targetScope','runId'];
  if (!object(binding) || !equal(Object.keys(binding).sort(),keys.sort())) fail('binding fields');
  if (!['job','project','runId'].every(k => typeof binding[k] === 'string' && binding[k].length > 0)) fail('binding identity');
  if (!Number.isSafeInteger(binding.build) || binding.build < 1 || !/^[a-f0-9]{40}$/.test(binding.source)) fail('build/source binding');
  if (!['candidate','runtime','project'].includes(binding.targetScope)) fail('target scope');
  if (typeof binding.candidate !== 'string' || !/^\S+@sha256:[a-f0-9]{64}$/.test(binding.candidate)) fail('pinned target binding');
  return binding;
}
