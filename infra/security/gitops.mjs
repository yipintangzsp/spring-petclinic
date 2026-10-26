import fs from 'node:fs';
import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {spawnSync} from 'node:child_process';
const lock=JSON.parse(fs.readFileSync('infra/security/tools-lock.json'));if(crypto.createHash('sha256').update(fs.readFileSync('infra/security/controller.json')).digest('hex')!==lock.kyverno.controller_manifest_sha256)throw Error('Reviewed controller manifest digest mismatch');
const rev=fs.readFileSync('.git-sha','utf8').trim();if(!/^[a-f0-9]{40}$/.test(rev))throw Error('Exact reviewed source revision required');
const repository=JSON.parse(fs.readFileSync('infra/devops-lab/applications/platform-rabbitmq.json')).spec.source.repoURL;
const endpoint=new URL(repository);if(endpoint.hostname!=='gitlab-service.ns-devops.svc.cluster.local'||endpoint.pathname!=='/root/petclinic-platform.git')throw Error('Existing private repository endpoint changed; review required');
const app={apiVersion:'argoproj.io/v1alpha1',kind:'Application',metadata:{name:'platform-devsecops',namespace:'argocd',labels:{'petclinic.devops.local/owner':'platform-devsecops'}},spec:{project:'default',source:{repoURL:repository,targetRevision:rev,path:'infra/security'},destination:{server:'https://kubernetes.default.svc',namespace:'devsecops-system'},syncPolicy:{automated:{prune:false,selfHeal:true},syncOptions:['CreateNamespace=true','ServerSideApply=true']}}};
const run=(args,input)=>{const x=spawnSync('kubectl',['--request-timeout=20s',...args],{input,encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});if(x.status!==0)throw Error(x.stderr.slice(-1200));return x.stdout;};
const old=run(['-n','argocd','get','application',app.metadata.name,'--ignore-not-found','-o','json']);if(old&&JSON.parse(old).metadata.labels?.['petclinic.devops.local/owner']!=='platform-devsecops')throw Error('Foreign GitOps application preserved');
run(['apply','-f','-'],JSON.stringify(app));
let last;
for(let i=0;i<90;i++){
 last=JSON.parse(run(['-n','argocd','get','application',app.metadata.name,'-o','json']));
 if(last.status?.sync?.revision===rev&&last.status.sync.status==='Synced'&&last.status?.health?.status==='Healthy')break;
 if(i===89)throw Error('DevSecOps GitOps sync did not become healthy: '+JSON.stringify(last.status?.conditions??last.status?.operationState?.message));
 await new Promise(r=>setTimeout(r,3000));
}
const desiredController=JSON.parse(fs.readFileSync('infra/security/controller.json'));
const names=desiredController.items.filter(x=>x.kind==='CustomResourceDefinition').map(x=>x.metadata.name);
const native=run(['get','crd',...names,'-o','jsonpath={range .items[*]}{.metadata.name}{" "}{range .status.conditions[*]}{.type}{"="}{.status}{","}{end}{"|"}{end}']);
const crds=native.split('|').filter(Boolean).map(line=>{const [name,states]=line.split(' ');if(!names.includes(name)||!states?.includes('Established=True')||!states.includes('NamesAccepted=True'))throw Error('CRD native readiness failed: '+name);return {name,conditions:states};});
if(crds.length!==names.length)throw Error('Missing CRD readiness evidence');
const desiredPolicy=JSON.parse(fs.readFileSync('infra/security/policies.json'));
const actualPolicy=JSON.parse(run(['get','clusterpolicy',desiredPolicy.metadata.name,'-o','json']));
if(!isDeepStrictEqual(actualPolicy.spec,desiredPolicy.spec))throw Error('Live policy contract differs from reviewed source');
fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/gitops.json',JSON.stringify({status:'success',source:rev,sync:last.status.sync,health:last.status.health,crds,livePolicySpecMatches:true},null,2));
console.log('DevSecOps GitOps pinned source synchronized and healthy');
