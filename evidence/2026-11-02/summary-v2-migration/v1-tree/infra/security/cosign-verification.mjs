// Nonzero Cosign exits are expected for negative fixtures only when the
// diagnostic identifies a signature failure, never for registry failures.
export function checkCosignVerification(kind, status, stderr) {
 if (!['signed','unsigned','wrong-key'].includes(kind) || !Number.isInteger(status)) throw Error('Invalid verification result');
 if (status !== 0 && !/no signatures found|no matching signatures|signature verification failed|invalid signature/i.test(String(stderr))) throw Error('Unexpected Cosign verification error: '+String(stderr).slice(-1000));
 if ((status === 0) !== (kind === 'signed')) throw Error('CLI signature negative case failed: '+kind);
 return status === 0;
}
