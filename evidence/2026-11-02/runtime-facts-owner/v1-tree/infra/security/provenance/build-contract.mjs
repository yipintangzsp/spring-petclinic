export const buildPredicateType='https://devops.local/attestation/image-build/v1';
export function validateBuildStatement(s,e){
 if(s.predicateType!==buildPredicateType||s.subject?.length!==1||s.subject[0].digest?.sha256!==e.image.split('@sha256:')[1])throw Error('Build subject mismatch');
 const p=s.predicate;const sha=x=>/^[a-f0-9]{64}$/.test(x??'');if(p.buildType!=='petclinic-maven-buildx-v1'||p.source?.commit!==e.commit||p.source?.repository!==e.repository||p.builder?.identity!==e.builder||String(p.builder?.buildNumber)!==String(e.buildNumber))throw Error('Build identity mismatch');
 if(p.candidateImage!==e.image||!sha(p.compilation?.jarSha256)||p.compilation.sourceCommit!==p.source.commit||!p.context?.files?.length||!sha(p.buildkit?.metadataSha256)||p.platforms?.join(',')!=='linux/amd64,linux/arm64')throw Error('Incomplete actual build evidence');
 if(!(Date.parse(p.startedAt)<=Date.parse(p.compilation.finishedAt)&&Date.parse(p.compilation.finishedAt)<=Date.parse(p.finishedAt)))throw Error('Invalid build chronology');
 if(p.context.files.some(x=>!x.name||!sha(x.sha256)))throw Error('Invalid context checksum');return p;
}
