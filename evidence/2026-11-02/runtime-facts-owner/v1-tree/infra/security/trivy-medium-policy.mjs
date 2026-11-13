export function classifyVulnerability(v,review,image){
 const severity=String(v.severity).toUpperCase();
 if(['CRITICAL','HIGH'].includes(severity))return {mode:'FAIL',reason:'Critical/High remain mandatory',finding:v};
 if(severity!=='MEDIUM')return {mode:'WARN',category:'low-or-informational',finding:v};
 const e=review.image===image?review.entries.find(x=>x.id===v.id&&x.package===v.package&&x.version===v.version):null;
 if(e?.mustFix===true&&e.reachability==='confirmed'&&e.fixVersion&&e.evidence?.positive&&e.evidence?.negative&&e.evidence?.businessPath)return {mode:'FAIL',category:'confirmed-reachable-fixable-medium',review:e,finding:v};
 return {mode:'WARN',category:e?.category??'unreviewed-medium',review:e??null,finding:v,reason:e?.reason??'New or changed finding: reachability/fix evidence requires review; not suppressed'};
}
