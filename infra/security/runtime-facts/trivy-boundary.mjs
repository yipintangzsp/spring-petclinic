export function authorizeTrivyRequest(url,method,c){
 const u=new URL(url),base=new URL(c.baseUrl);if(u.origin!==base.origin||u.username||u.password)throw Error('TRIVY_BOUNDARY: external/copy fallback denied');
 const p=c.repositoryPath;if(!u.pathname.startsWith(p))throw Error('TRIVY_BOUNDARY: non-validation repository action denied');
 const tail=u.pathname.slice(p.length),m=/^(sha256:[a-f0-9]{64})(\/scan|\/additions\/vulnerabilities)?$/.exec(tail);
 if(!m||!c.selectedDigests.includes(m[1]))throw Error('TRIVY_BOUNDARY: candidate/report binding mismatch');
 if(method==='GET'&&['','?with_scan_overview=true'].includes(u.search)&&m[2]!=='/scan')return {method,path:u.pathname+u.search,digest:m[1],classification:'READ_ONLY_REQUIRED'};
 if(method==='POST'&&m[2]==='/scan'&&!u.search&&c.scanDigests.includes(m[1])&&!c.protectedDigests.includes(m[1]))return {method,path:u.pathname,digest:m[1],classification:'SCAN_TRIGGER_REQUIRED'};
 throw Error('TRIVY_BOUNDARY: push/delete/tag/protected scan denied');
}
export function authorizeTrivyKube(args,c){
 const a=args.filter(v=>!v.startsWith('--request-timeout='));if(a[0]!=='-n'||a[1]!=='petclinic')throw Error('TRIVY_BOUNDARY: unapproved Kubernetes namespace');
 const x=a.slice(2);if(JSON.stringify(x)==='["get","deploy","petclinic","-o","json"]')return {kind:'read-deployment'};
 if(JSON.stringify(x)===JSON.stringify(['get','pods','-l',c.selector,'-o','json']))return {kind:'read-pods'};
 if(x[0]==='exec'&&c.pods.some(p=>p.name===x[1])&&JSON.stringify(x.slice(2))==='["-c","petclinic","--","cat","/proc/1/maps"]')return {kind:'read-runtime-maps',pod:c.pods.find(p=>p.name===x[1])};
 throw Error('TRIVY_BOUNDARY: non-read-only Kubernetes operation denied');
}
