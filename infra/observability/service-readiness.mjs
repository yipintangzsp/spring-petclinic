// Use the authenticated Rails API: health endpoints are localhost-only by default.
export async function waitGitLabReady(base, {
 timeoutMs=600000, pollMs=10000, requestTimeoutMs=10000, headers={},
}={}) {
 const deadline=Date.now()+timeoutMs;
 while(Date.now()<deadline) {
  let permanentError;
  try {
   const response=await fetch(base+'/api/v4/user', {headers,
    signal:AbortSignal.timeout(Math.max(1,Math.min(requestTimeoutMs,deadline-Date.now()))),
   });
   if([401,403,404].includes(response.status)) {
    permanentError=new Error(`GitLab readiness endpoint: HTTP ${response.status}`);
   }
   if(response.ok) {
    const body=await response.json();
    if(Number.isInteger(body.id)&&body.id>0&&typeof body.username==='string'&&body.username)return body;
   } else await response.body?.cancel();
  } catch(error) { /* Transport failures and startup responses remain bounded. */ }
  if(permanentError)throw permanentError;
  const remaining=deadline-Date.now();
  if(remaining<=0)break;
  console.log('GitLab Rails not ready; waiting before source mirror');
  await new Promise(resolve=>setTimeout(resolve,Math.min(pollMs,remaining)));
 }
 throw new Error(`GitLab readiness timed out after ${timeoutMs} ms; source mirror not attempted`);
}
