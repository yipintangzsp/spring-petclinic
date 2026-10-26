import {randomInt} from 'node:crypto';
// Generate only inside the isolated scanner. Never a credential issued by a service.
// Unique characters avoid probabilistic entropy failures in the scanner canary.
export function syntheticCredential() {
 const chars=Array.from('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');
 for(let i=chars.length-1;i>0;i--){const j=randomInt(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
 return ['ghp',chars.slice(0,36).join('')].join('_');
}
