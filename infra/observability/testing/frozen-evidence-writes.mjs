// Accidental-write protection for TRUSTED test replays, not an OS security sandbox.
// Loaded with --import before the unchanged tests. Historical files stay read-only
// to this Node API layer; all write destinations must be in its disposable tree.
import fs from 'node:fs';import fsp from 'node:fs/promises';import path from 'node:path';import {syncBuiltinESMExports} from 'node:module';
import {fileURLToPath} from 'node:url';
const requested=process.env.TRIVY_FROZEN_REPLAY_ROOT;
if(!requested)throw Error('FROZEN_REPLAY_PRIVATE_ROOT_REQUIRED');
const root=fs.realpathSync(requested),st=fs.statSync(root);
if(root!==fs.realpathSync(process.cwd())||st.uid!==process.getuid()||(st.mode&0o077)
 ||!fs.existsSync(path.join(root,'.frozen-replay.json')))throw Error('FROZEN_REPLAY_IDENTITY_REQUIRED');
const roots=new Map([[root,{dev:st.dev,ino:st.ino}]]),fds=new Map();
const contained=(base,p)=>{const r=path.relative(base,p);return !r||r!=='..'&&!r.startsWith('..'+path.sep)&&!path.isAbsolute(r);};
const beneath=p=>[...roots].some(([base,id])=>{try{const s=fs.statSync(base);return s.dev===id.dev&&s.ino===id.ino&&contained(base,p);}catch{return false;}});
function check(value){
 if(typeof value==='number'){const entry=fds.get(value),s=fs.fstatSync(value);if(!entry||entry.dev!==s.dev||entry.ino!==s.ino)throw Error('FROZEN_EVIDENCE_UNTRACKED_FD_WRITE_DENIED');check(entry.path);return;}
 if(value instanceof URL)value=fileURLToPath(value);
 const target=path.resolve(String(value));
 let current=target;while(!fs.existsSync(current)){const next=path.dirname(current);if(next===current)throw Error('FROZEN_REPLAY_PATH_UNKNOWN');current=next;}
 const canonical=path.resolve(fs.realpathSync(current),path.relative(current,target));
 if(!beneath(canonical))throw Error('FROZEN_EVIDENCE_WRITE_OUTSIDE_REPLAY_DENIED');
}
function registerTemp(created){const p=fs.realpathSync(created),s=fs.statSync(p);if(s.uid!==process.getuid()||(s.mode&0o077))throw Error('FROZEN_REPLAY_TEMP_IDENTITY_INVALID');roots.set(p,{dev:s.dev,ino:s.ino});return created;}
function tempPrefix(value){
 try{check(value);return;}catch(e){
  const parent=fs.realpathSync(path.dirname(String(value)));
  if(!['/tmp','/private/tmp'].some(p=>{try{return parent===fs.realpathSync(p);}catch{return false;}}))throw e;
 }
}
function registerFd(fd,value){const s=fs.fstatSync(fd);fds.set(fd,{dev:s.dev,ino:s.ino,path:value});return fd;}
const writing=flags=>typeof flags==='number'?Boolean(flags&(fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND)):flags!=='r'&&flags!=='rs';
for(const api of [fs,fsp]){
 for(const name of ['writeFile','appendFile','mkdir','mkdtemp','rm','rmdir','unlink','truncate','chmod','chown','utimes',
  'writeFileSync','appendFileSync','mkdirSync','mkdtempSync','rmSync','rmdirSync','unlinkSync','truncateSync','chmodSync','chownSync','utimesSync']){
  if(typeof api[name]!=='function')continue;const original=api[name];api[name]=function(value,...args){
   if(name==='mkdtempSync'){tempPrefix(value);return registerTemp(original.call(this,value,...args));}
   if(name==='mkdtemp'&&api===fsp){tempPrefix(value);return original.call(this,value,...args).then(registerTemp);}
   if(name==='mkdtemp'&&api===fs){tempPrefix(value);const callback=args.pop();return original.call(this,value,...args,(e,p)=>callback(e,e?p:registerTemp(p)));}
   check(value);return original.call(this,value,...args);};
 }
 for(const name of ['rename','renameSync','copyFile','copyFileSync','cp','cpSync','link','linkSync']){
  if(typeof api[name]!=='function')continue;const original=api[name];api[name]=function(from,to,...args){if(name.startsWith('rename'))check(from);check(to);return original.call(this,from,to,...args);};
 }
 for(const name of ['symlink','symlinkSync']){
  if(typeof api[name]!=='function')continue;const original=api[name];api[name]=function(target,destination,...args){check(destination);return original.call(this,target,destination,...args);};
 }
 for(const name of ['open','openSync']){
  if(typeof api[name]!=='function')continue;const original=api[name];api[name]=function(value,flags,...args){
   if(!writing(flags))return original.call(this,value,flags,...args);check(value);
   if(name==='openSync')return registerFd(original.call(this,value,flags,...args),value);
   if(api===fsp)return original.call(this,value,flags,...args).then(h=>{registerFd(h.fd,value);return h;});
   const callback=args.pop();return original.call(this,value,flags,...args,(e,fd)=>callback(e,e?fd:registerFd(fd,value)));
  };
 }
}
const stream=fs.createWriteStream;fs.createWriteStream=function(value,...args){check(value);return stream.call(this,value,...args);};
syncBuiltinESMExports();
