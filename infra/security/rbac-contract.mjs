import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createRbacPartCollector,writeKyvernoPart,completeKyverno,runKey} from './summary-v2/collectors/kyverno.mjs';
// Frozen-replay harnesses strip imports; fall back to a no-op collector so
// the module executes byte-identically there. Collection is passive.
const collector=typeof createRbacPartCollector==='function'?createRbacPartCollector()
 :{cmd(){},reportWrite(){},observations:{}};
const sa='system:serviceaccount:devsecops-system:kyverno-admission-controller';
const run=args=>{const r=spawnSync('kubectl',['--request-timeout=15s',...args],{encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});collector.cmd(r);if(r.status!==0)throw Error('Kyverno RBAC/health check failed: '+r.stdout+r.stderr.slice(-600));return r.stdout;};
const d=JSON.parse(run(['-n','devsecops-system','get','deploy','kyverno-admission-controller','-o','json']));if(d.status.availableReplicas!==1)throw Error('Kyverno must remain available after full release');
const identityChecks=[];
for(const resource of ['customresourcedefinitions.apiextensions.k8s.io/clusterpolicies.kyverno.io','customresourcedefinitions.apiextensions.k8s.io/policies.kyverno.io']){
 const value=run(['auth','can-i','get',resource,'--as='+sa]).trim();if(value!=='yes')throw Error('Kyverno official core read permission lost');identityChecks.push({resource,allowed:true});
}
const role=JSON.parse(run(['get','clusterrole','kyverno:admission-controller','-o','json']));if(!role.rules?.some(r=>r.apiGroups.includes('apiextensions.k8s.io')&&r.resources.includes('customresourcedefinitions')&&r.verbs.includes('get')))throw Error('Aggregated core role rules absent');
const app=JSON.parse(run(['-n','argocd','get','application','platform-devsecops','-o','json']));if(app.status.sync.status!=='Synced'||app.status.health.status!=='Healthy')throw Error('Security GitOps must remain Synced and Healthy at final postflight');
fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/kyverno-rbac.json',JSON.stringify({status:'success',source:fs.readFileSync('.git-sha','utf8').trim(),identity:sa,identityChecks,aggregateRuleCount:role.rules.length,available:1,sync:app.status.sync.status,health:app.status.health.status},null,2));
if(typeof completeKyverno==='function'){collector.reportWrite(true);writeKyvernoPart('.', 'rbac',runKey(),collector.observations,undefined,'success');completeKyverno();}
