import fs from 'node:fs';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {requireLease} from '../scanner-runtime.mjs';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from './health-contract.mjs';
requireLease();
const mode=process.argv[2]??'check';if(!['baseline','check'].includes(mode))throw Error('Use baseline/check');
const lock=JSON.parse(fs.readFileSync('infra/security/runtime/lock.json'));
if(crypto.createHash('sha256').update(fs.readFileSync('infra/security/runtime/falco.json')).digest('hex')!==lock.manifestSha256)throw Error('Runtime manifest integrity mismatch');
const run=a=>{const r=spawnSync('kubectl',['--request-timeout=15s',...a],{encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});if(r.status!==0)throw Error(r.stderr.slice(-1200));return r.stdout;};
const d=JSON.parse(run(['-n','devsecops-system','get','ds','platform-falco','-o','json']));
if(d.status.desiredNumberScheduled!==1||d.status.numberReady!==1||d.status.updatedNumberScheduled!==1)throw Error('Expected exactly one current ready local Falco');
const ps=JSON.parse(run(['-n','devsecops-system','get','pods','-l','app.kubernetes.io/name=falco','-o','json'])).items.filter(p=>!p.metadata.deletionTimestamp);
if(ps.length!==1||ps[0].spec.nodeName!=='devops'||!ps[0].spec.containers[0].image.endsWith(lock.arm64ManifestDigest))throw Error('Unexpected Falco coverage or image');
if(ps[0].metadata.labels['petclinic.devops.local/runtime-ruleset']!==lock.rulesetLabel)throw Error('Unexpected runtime rule version');
const c=ps[0].status.containerStatuses.find(x=>x.name==='falco');
const node=JSON.parse(run(['get','node','devops','-o','json']));
const current={podUid:ps[0].metadata.uid,nodeBootId:node.status.nodeInfo.bootID,containerId:c?.containerID,runningSince:c?.state?.running?.startedAt,image:ps[0].spec.containers[0].image,restarts:c?.restartCount,ready:c?.ready,priorExit:c?.lastState?.terminated};
const source=fs.readFileSync('.git-sha','utf8').trim(),baselineFile='.devsecops/runtime-baseline.json';
let baseline;
if(mode==='baseline'){
 validatePriorExit(current);
 if(!current.nodeBootId||!current.containerId||!Number.isFinite(Date.parse(current.runningSince))||Date.now()-Date.parse(current.runningSince)<120000)throw Error('Stable running Falco identity required before baseline');
 baseline={...current,source,build:String(process.env.BUILD_NUMBER),capturedAt:new Date().toISOString()};
}else{
 if(!fs.existsSync(baselineFile))throw Error('Current build runtime baseline missing');
 baseline=JSON.parse(fs.readFileSync(baselineFile));
 if(baseline.source!==source||baseline.build!==String(process.env.BUILD_NUMBER))throw Error('Foreign runtime baseline preserved');
 validateRuntimeContinuity(current,baseline);
}
const log=run(['-n','devsecops-system','logs',ps[0].metadata.name,'-c','falco',mode==='baseline'?'--since=10m':'--since-time='+baseline.capturedAt,'--tail=500']);
const diagnostics=driverDiagnostics(log);if(diagnostics.fatalDriverLines)throw Error('Falco fatal/driver/rule error requires review');
const r=await fetch('http'+ '://'+ps[0].status.podIP+':8765/healthz',{signal:AbortSignal.timeout(5000)});if(!r.ok)throw Error('Falco actual health endpoint failed');
fs.mkdirSync('.devsecops',{recursive:true});if(mode==='baseline')fs.writeFileSync(baselineFile,JSON.stringify(baseline,null,2),{mode:0o600});fs.writeFileSync('.devsecops/runtime-health.json',JSON.stringify({status:'success',source:fs.readFileSync('.git-sha','utf8').trim(),node:'devops',pod:ps[0].metadata.name,image:ps[0].spec.containers[0].image,ready:true,ruleset:lock.rulesetLabel,restarts:c.restartCount,baselineRestarts:baseline.restarts,newRestarts:c.restartCount-baseline.restarts,nodeBootId:current.nodeBootId,podUid:current.podUid,mode,diagnostics,diagnosticWindow:{since:mode==='baseline'?'last-10-minutes':baseline.capturedAt,tail:500},http:r.status,scope:'Health only; ordinary runtime events do not fail CI; cloud workers not covered'},null,2));
