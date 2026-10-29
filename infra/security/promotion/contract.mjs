const imagePattern=/^core\.harbor\.domain\/petclinic\/petclinic@sha256:[a-f0-9]{64}$/;
export function validateGate(x){
 if(x.result!=='SUCCESS'||!Number.isInteger(x.build)||x.build<1||!/^[a-f0-9]{40}$/.test(x.source))throw Error('Successful identified Security Gate required');
 if(!imagePattern.test(x.candidate)||x.trivy.status!=='success'||x.trivy.targetScope!=='candidate'||x.trivy.auditTargetImage!==x.candidate||x.summary.auditTargetImage!==x.candidate||x.summary.targetScope!=='candidate')throw Error('Gate/candidate identity mismatch');
 if(x.summary.source!==x.source||x.summary.build!==x.build)throw Error('Stale summary');
 if(x.summary.trivy_critical!==0||x.summary.trivy_high!==0||x.trivy.scans?.length!==2)throw Error('Complete dual-architecture C/H=0 gate required');
 for(const key of ['sourceScan','admission','semgrep','zap','falco','dojo','kubescape'])if(x[key]?.status!=='success'||(x[key].source&&x[key].source!==x.source))throw Error('Security evidence incomplete: '+key);
 if(!x.business.unchanged||!imagePattern.test(x.trivy.runtimeImage))throw Error('Stable runtime snapshot required');
 if(x.sbom.candidate!==x.candidate||x.sbom.architectures?.length!==2||new Set(x.sbom.architectures.map(a=>a.arch)).size!==2||x.sbom.architectures.some(a=>!['amd64','arm64'].includes(a.arch)||!/^sha256:[a-f0-9]{64}$/.test(a.jarSha256)||!/^sha256:[a-f0-9]{64}$/.test(a.sbomSha256)))throw Error('Candidate-bound SBOM evidence required');
 return x.candidate.split('@')[1];
}
export function approvedRelease(x,signing){
 const digest=validateGate(x);const required=[digest,...x.trivy.scans.map(s=>s.digest)];
 if(!required.every(d=>signing.images?.some(i=>i.image==='core.harbor.domain/petclinic/petclinic@'+d&&i.verified)))throw Error('Candidate and runtime children must pass actual Cosign verification');
 return {schema:1,status:'APPROVED',securityGate:'SUCCESS',jenkinsBuild:x.build,securitySourceCommit:x.source,candidateImage:x.candidate,candidateDigest:digest,approvedDigest:digest,previousRuntimeImage:x.trivy.runtimeImage,candidateSbom:x.sbom,verifiedImages:signing.images,createdAt:new Date().toISOString()};
}
export function promotionInput(approval,manifest){
 if(approval.status!=='APPROVED'||approval.securityGate!=='SUCCESS'||approval.candidateDigest!==approval.approvedDigest||approval.candidateImage!=='core.harbor.domain/petclinic/petclinic@'+approval.approvedDigest||!imagePattern.test(approval.candidateImage)||!imagePattern.test(approval.previousRuntimeImage))throw Error('Approved digest identity required before any Git mutation');
 const re=/^([ \t]*image:\s+)(?:core\.harbor\.domain|10\.0\.0\.3:30050)\/petclinic\/petclinic@sha256:[a-f0-9]{64}[ \t]*$/gm;const matches=[...manifest.matchAll(re)];if(matches.length!==1||!matches[0][0].trim().endsWith(approval.previousRuntimeImage))throw Error('GitOps runtime moved; preserve concurrent work');
 return manifest.replace(re,(_,prefix)=>prefix+approval.candidateImage);
}
