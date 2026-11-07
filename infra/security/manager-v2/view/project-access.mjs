// Local operator credential and project-scoped capabilities. No production authority.
import fs from 'node:fs';import path from 'node:path';import {randomBytes,timingSafeEqual,createHmac} from 'node:crypto';
import {sbomProjects} from '../sbom-real.mjs';
const file=new URL('../../../../.devsecops/security-view-project-access-v1.json',import.meta.url);
const secret=()=>randomBytes(32).toString('hex');
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
export function accessCredentials(){
 const parent=path.dirname(file.pathname),st=fs.lstatSync(parent);if(st.uid!==process.getuid()||(st.mode&0o022)||fs.realpathSync(parent)!==parent)throw Error('UNSAFE_ACCESS_STORAGE');
 let v;
 try{const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o077)||s.nlink!==1||s.size>16384)throw Error('UNSAFE_ACCESS_STORAGE');v=JSON.parse(fs.readFileSync(fd));}finally{fs.closeSync(fd);}}catch(e){if(e.code!=='ENOENT')throw e;}
 if(!v){v={schemaVersion:1,operatorToken:secret(),projects:Object.fromEntries(Object.keys(sbomProjects()).map(p=>[p,secret()]))};const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,JSON.stringify(v));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 if(v.schemaVersion!==1||!/^[a-f0-9]{64}$/.test(v.operatorToken)||Object.keys(v.projects).sort().join(',')!==Object.keys(sbomProjects()).sort().join(',')||Object.values(v.projects).some(t=>!/^[a-f0-9]{64}$/.test(t)))throw Error('INVALID_PROJECT_ACCESS_CONFIGURATION');
 return v;
}
export function projectAccess(){
 const credentials=accessCredentials(),tickets=new Map();
 const sign=expires=>createHmac('sha256',credentials.operatorToken).update('local-operator-cookie-v1:'+expires).digest('hex');
 const validCookie=req=>{const v=(req.headers.cookie??'').split(';').map(s=>s.trim()).find(s=>s.startsWith('smv2_operator='))?.slice(14),parts=v?.split('.');return parts?.length===2&&Number(parts[0])>Date.now()&&Number(parts[0])<=Date.now()+3600000&&same(parts[1],sign(parts[0]));};
 const operator=req=>same(req.headers.authorization,'Bearer '+credentials.operatorToken)||validCookie(req);
 const project=req=>Object.entries(credentials.projects).find(([,token])=>same(req.headers['x-project-token'],token))?.[0]??null;
 return {operator,project,authorized:(req,id)=>Object.hasOwn(credentials.projects,id)&&(operator(req)||project(req)===id),
  sessions(req){if(operator(req))return Object.entries(credentials.projects).map(([projectId,projectToken])=>({projectId,projectToken}));const id=project(req);return id?[{projectId:id,projectToken:credentials.projects[id]}]:null;},
  ticket(req){if(!same(req.headers.authorization,'Bearer '+credentials.operatorToken))return null;for(const [t,at]of tickets)if(at<Date.now())tickets.delete(t);if(tickets.size>=8)return null;const token=secret();tickets.set(token,Date.now()+30000);return token;},
  consume(token){const expires=tickets.get(token);tickets.delete(token);if(!(expires>Date.now()))return null;const until=String(Date.now()+3600000);return 'smv2_operator='+until+'.'+sign(until)+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600';}
 };
}
