import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const file='.devsecops/source-gate.json';if(!fs.existsSync(file))process.exit(0);
const r=JSON.parse(fs.readFileSync(file));
if(!r.uid||r.cleanup)process.exit(0);
if(!/^\d+$/.test(process.env.BUILD_NUMBER??'')||!r.pod.startsWith('source-'+process.env.BUILD_NUMBER+'-')||r.namespace!=='devsecops-execution')throw Error('Refuse cleanup outside this exact CI run');
const k=args=>{const x=spawnSync('kubectl',['--request-timeout=10s',...args],{encoding:'utf8',timeout:60000});if(x.status!==0)throw Error(x.stderr);return x.stdout;};
const raw=k(['-n',r.namespace,'get','pod',r.pod,'--ignore-not-found','-o','json']);
if(raw){const p=JSON.parse(raw);if(p.metadata.uid!==r.uid||p.metadata.labels?.['petclinic.devops.local/owner']!=='platform-devsecops')throw Error('Replacement or foreign Pod preserved');k(['-n',r.namespace,'delete','pod',r.pod,'--wait=true','--timeout=45s']);}
r.cleanup=true;r.cleanupFromPost=true;fs.writeFileSync(file,JSON.stringify(r,null,2));
