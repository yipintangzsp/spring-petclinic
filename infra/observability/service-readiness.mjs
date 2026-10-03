// Wait for Rails, not just GitLab's nginx listener. Readiness uses no credentials.
export async function waitGitLabReady(base, {
 timeoutMs=600000, pollMs=10000, requestTimeoutMs=10000,
}={}) {
 const deadline=Date.now()+timeoutMs;
 while(Date.now()<deadline) {
  let permanentError;
  try {
   const response=await fetch(base+'/-/readiness', {
    signal:AbortSignal.timeout(Math.max(1,Math.min(requestTimeoutMs,deadline-Date.now()))),
   });
   if([401,403,404].includes(response.status)) {
    permanentError=new Error(`GitLab readiness endpoint: HTTP ${response.status}`);
   }
   if(response.ok) {
    const body=await response.json();
    if(body.status==='ok')return;
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
