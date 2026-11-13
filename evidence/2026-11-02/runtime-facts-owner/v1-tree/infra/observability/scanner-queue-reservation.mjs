import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
export function reservationInput(mode,holder,job,build){
 if(!['reserve','status','release'].includes(mode)||!/^jenkins-petclinic-\d+$|^ci-scanner-slot-proof[^ ]*$/.test(holder)||job!=='petclinic-ci'||!Number.isSafeInteger(Number(build))||Number(build)<1)throw Error('Exact scanner queue owner required');
 return {mode,holder,job,build:Number(build)};
}
export function scannerQueue(mode,holder){
 const input=reservationInput(mode,holder,process.env.JOB_NAME,process.env.BUILD_NUMBER);
 const script=fs.readFileSync(new URL('./scanner-queue-reservation.groovy',import.meta.url),'utf8').replace('INPUT_BASE64',Buffer.from(JSON.stringify(input)).toString('base64'));
 const code=`const fs=require('fs');(async()=>{const i=JSON.parse(fs.readFileSync(0,'utf8'));const base=process.env.JENKINS_URL;const h={Authorization:'Basic '+Buffer.from(process.env.JENKINS_USER+':'+process.env.JENKINS_PASS).toString('base64')};const c=await fetch(base+'/crumbIssuer/api/json',{headers:h,signal:AbortSignal.timeout(5000)});if(!c.ok)throw Error('Crumb HTTP '+c.status);const x=await c.json();h[x.crumbRequestField]=x.crumb;h.Cookie=c.headers.getSetCookie().map(x=>x.split(';')[0]).join('; ');h['Content-Type']='application/x-www-form-urlencoded';const r=await fetch(base+'/scriptText',{method:'POST',headers:h,body:new URLSearchParams({script:i.script}),signal:AbortSignal.timeout(20000)});if(!r.ok)throw Error('Queue reservation HTTP '+r.status);console.log(await r.text());})().catch(e=>{console.error(e.message);process.exit(1)});`;
 const r=spawnSync('kubectl',['--request-timeout=25s','-n','ns-devops','exec','-i','deploy/github-webhook-relay','--','node','--max-old-space-size=24','-e',code],{input:JSON.stringify({script}),encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
 const line=r.stdout?.split(/\r?\n/).find(x=>x.startsWith('SCANNER_QUEUE_JSON '));
 if(r.status!==0||!line)throw Error('Queue reservation not proven: '+String(r.stderr||r.stdout).slice(-500));
 const result=JSON.parse(line.slice('SCANNER_QUEUE_JSON '.length));
 if(result.holder!==holder||result.quietingDown||result.reserved!==(mode!=='release'))throw Error('Queue reservation state differs');
 return result;
}
