import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
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
fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/gitops.json',JSON.stringify({status:'success',source:rev,sync:last.status.sync,health:last.status.health},null,2));
console.log('DevSecOps GitOps pinned source synchronized and healthy');
