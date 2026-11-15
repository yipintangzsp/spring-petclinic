import crypto from 'node:crypto';
export const predicateType='https://devops.local/attestation/security-validation/v1';
export function validate(statement,expected){
 if(statement._type!=='https://in-toto.io/Statement/v0.1'||statement.predicateType!==predicateType||statement.subject?.length!==1||statement.subject[0].name!==expected.image.split('@sha256:')[0]||statement.subject[0].digest?.sha256!==expected.image.split('@sha256:')[1])throw Error('Candidate subject mismatch');
 const p=statement.predicate;
 for(const k of ['repository','commit','buildNumber','builderIdentity','pipelineIdentity','candidateImage'])if(p[k]!==expected[k])throw Error('Provenance identity mismatch: '+k);
 if(!Number.isFinite(Date.parse(p.buildTimestamp))||p.buildType!=='candidate-security-validation')throw Error('Invalid build context');return true;
}
export function verifyEnvelope(e,key){if(e.payloadType!=='application/vnd.in-toto+json')throw Error('Unexpected envelope payloadType');const type=Buffer.from(e.payloadType),payload=Buffer.from(e.payload,'base64');const pae=Buffer.concat([Buffer.from('DSSEv1 '+type.length+' '),type,Buffer.from(' '+payload.length+' '),payload]);if(!e.signatures?.some(s=>crypto.verify('sha256',pae,key,Buffer.from(s.sig,'base64'))))throw Error('Invalid DSSE signature');return JSON.parse(payload);}
