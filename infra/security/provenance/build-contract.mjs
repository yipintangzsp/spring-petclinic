export const buildPredicateType='https://devops.local/attestation/image-build/v1';
export function validateBuildStatement(s,e){
 if(s._type!=='https://in-toto.io/Statement/v0.1'||s.predicateType!==buildPredicateType||s.subject?.length!==1||s.subject[0].name!==e.image.split('@sha256:')[0]||s.subject[0].digest?.sha256!==e.image.split('@sha256:')[1])throw Error('Build subject mismatch');
 const p=s.predicate;const sha=x=>/^[a-f0-9]{64}$/.test(x??'');if(p.buildType!=='petclinic-maven-buildx-v1'||p.source?.commit!==e.commit||p.source?.repository!==e.repository||p.builder?.identity!==e.builder||String(p.builder?.buildNumber)!==String(e.buildNumber))throw Error('Build identity mismatch');
 if(p.candidateImage!==e.image||!sha(p.compilation?.jarSha256)||p.compilation.sourceCommit!==p.source.commit||!p.context?.files?.length||!sha(p.buildkit?.metadataSha256)||p.platforms?.join(',')!=='linux/amd64,linux/arm64')throw Error('Incomplete actual build evidence');
 if(p.buildkit?.outputDigest!=='sha256:'+s.subject[0].digest.sha256||p.compilation?.source?.commit!==p.source.commit||p.compilation?.source?.repository!==p.source.repository||p.compilation?.builder?.identity!==p.builder.identity||String(p.compilation?.builder?.buildNumber)!==String(p.builder.buildNumber))throw Error('Build evidence inconsistency');
 if(!(Date.parse(p.startedAt)<=Date.parse(p.compilation.startedAt)&&Date.parse(p.compilation.startedAt)<=Date.parse(p.compilation.finishedAt)&&Date.parse(p.compilation.finishedAt)<=Date.parse(p.finishedAt)))throw Error('Invalid build chronology');
 if(p.context.files.some(x=>!x.name||!sha(x.sha256)))throw Error('Invalid context checksum');return p;
}
