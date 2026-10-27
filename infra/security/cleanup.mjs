import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const k=(args,input)=>{const x=spawnSync('kubectl',['--request-timeout=10s',...args],{input,encoding:'utf8',timeout:60000});if(x.status!==0)throw Error(x.stderr);return x.stdout;};
for(const kind of ['source','semgrep','zap']){
 const file='.devsecops/'+kind+'-gate.json';if(!fs.existsSync(file))continue;
 const r=JSON.parse(fs.readFileSync(file));if(!r.uid||r.cleanup)continue;
 if(!/^\d+$/.test(process.env.BUILD_NUMBER??'')||!r.pod.startsWith(kind+'-'+process.env.BUILD_NUMBER+'-')||r.namespace!=='devsecops-execution')throw Error('Refuse cleanup outside this exact CI run');
 const raw=k(['-n',r.namespace,'get','pod',r.pod,'--ignore-not-found','-o','json']);
 if(raw){const p=JSON.parse(raw);if(p.metadata.uid!==r.uid||p.metadata.labels?.['petclinic.devops.local/owner']!=='platform-devsecops')throw Error('Replacement or foreign Pod preserved');
  k(['delete','--raw',`/api/v1/namespaces/${r.namespace}/pods/${r.pod}`,'-f','-'],JSON.stringify({apiVersion:'v1',kind:'DeleteOptions',preconditions:{uid:r.uid}}));
  k(['-n',r.namespace,'wait','--for=delete','pod/'+r.pod,'--timeout=45s']);
 }
 r.cleanup=true;r.cleanupFromPost=true;fs.writeFileSync(file,JSON.stringify(r,null,2));
}
