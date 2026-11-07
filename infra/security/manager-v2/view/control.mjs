import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {accessCredentials} from './project-access.mjs';
import {randomUUID,createHash} from 'node:crypto';
const here=fs.realpathSync(new URL('.',import.meta.url));
const state=path.join(os.tmpdir(),`security-v2-view-${process.getuid()}-${createHash('sha256').update(here).digest('hex').slice(0,12)}`);
const record=path.join(state,'process.json');
if (!fs.existsSync(state)) fs.mkdirSync(state,{mode:0o700});
const st=fs.lstatSync(state);
if (!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)) throw Error('Unsafe local state directory');
async function health(){try{return await (await fetch('http://127.0.0.1:17862/api/health',{signal:AbortSignal.timeout(1500)})).json();}catch{return null;}}
async function stop(){
  if (!fs.existsSync(record)) {console.log('No managed page process');return;}
  const r=JSON.parse(fs.readFileSync(record));const h=await health();
  if(!h){try{process.kill(r.pid,0);throw Error('Unresponsive process: refusing to signal without ownership proof');}catch(e){if(e.code!=='ESRCH')throw e;}fs.unlinkSync(record);return;}
  if(h.instance!==r.instance||h.pid!==r.pid||h.service!=='security-manager-v2-readonly')throw Error('Process ownership mismatch');
  process.kill(r.pid,'SIGTERM');
  for(let i=0;i<30;i++){await new Promise(r=>setTimeout(r,100));if(!(await health())){fs.unlinkSync(record);console.log('Stopped local page');return;}}
  throw Error('Page did not stop; no global kill attempted');
}
async function start(){
  const h=await health();if(h){if(h.service!=='security-manager-v2-readonly')throw Error('Port occupied');console.log('Already running: http://127.0.0.1:17862');return;}
  if(fs.existsSync(record))throw Error('Stale process record: run stop before start');
  const instance=randomUUID();const log=fs.openSync(path.join(state,'server.log'),'a',0o600);
  const child=spawn(process.execPath,[path.join(here,'server.mjs')],{detached:true,stdio:['ignore',log,log],env:{PATH:process.env.PATH,LANG:process.env.LANG??'en_US.UTF-8',TZ:'Asia/Shanghai',SECURITY_VIEW_INSTANCE:instance}});
  child.unref();fs.closeSync(log);
  fs.writeFileSync(record,JSON.stringify({pid:child.pid,instance}),{flag:'wx',mode:0o600});
  for(let i=0;i<30;i++){await new Promise(r=>setTimeout(r,100));const h=await health();if(h?.instance===instance){console.log('Running: http://127.0.0.1:17862');return;}}
  throw Error(`Startup not verified; inspect ${path.join(state,'server.log')}`);
}
const action=process.argv[2]??'status';
if(action==='restart'){await stop();await start();}
else if(action==='start')await start();
else if(action==='stop')await stop();
else if(action==='open'){
 await start();const base='http://127.0.0.1:17862',s=await(await fetch(base+'/api/plugins')).json();
 const r=await fetch(base+'/api/sbom/operator-ticket',{method:'POST',headers:{Origin:base,'Content-Type':'application/json','X-CSRF-Token':s.csrfToken,Authorization:'Bearer '+accessCredentials().operatorToken},body:'{}'});
 if(!r.ok)throw Error('Local operator authorization failed');const {ticket}=await r.json();
 await promisify(execFile)('/usr/bin/open',['http://security.devops.local:17862/operator-login?ticket='+ticket]);
 console.log('Opened authorized local page: http://security.devops.local:17862/#candidate-overview');
}
else if(action==='status')console.log(await health()??'STOPPED');
else throw Error('Use start | stop | restart | status | open');
