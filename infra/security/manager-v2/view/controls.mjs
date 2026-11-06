// Local persistence adapter for the EXISTING Candidate configuration resolver.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {configuration} from '../config.mjs';
import {realThreePluginsRegistry} from '../registry.mjs';
import {digest} from '../../summary-v2/codec.mjs';
const file=new URL('../../../../.devsecops/security-view-controls-v1.json',import.meta.url);
export const managedPlugins=Object.freeze(['gitleaks','semgrep','cosign']);
const error=(code,status=400)=>Object.assign(Error(code),{code,status});
const exact=(x,keys)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
export const demoDefaults=()=>({enabled:true,securityLevel:'standard',plugins:Object.fromEntries(managedPlugins.map(id=>[id,{enabled:true}]))});
function resolve(settings){
 if(!exact(settings,['enabled','securityLevel','plugins'])||!exact(settings.plugins,managedPlugins)||managedPlugins.some(id=>!exact(settings.plugins[id],['enabled'])))throw error('INVALID_CANDIDATE_CONFIGURATION');
 const registry=realThreePluginsRegistry();
 try{return configuration({security:{...settings,globalMode:'audit',profile:'java-web',policyVersion:'baseline-v1'}},'web-controlled-fixture',registry.ids(),Object.fromEntries(registry.ids().map(id=>[id,managedPlugins.includes(id)])));}
 catch{throw error('INVALID_CANDIDATE_CONFIGURATION');}
}
function parent(){const dir=path.dirname(file.pathname);const s=fs.lstatSync(dir);if(fs.realpathSync(dir)!==dir||!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o022))throw error('UNSAFE_CONTROL_DIRECTORY',503);return dir;}
function raw(){
 parent();let present;try{present=fs.lstatSync(file);}catch(e){if(e.code!=='ENOENT')throw e;}if(!present)return {schemaVersion:1,revision:0,updatedAt:null,settings:demoDefaults(),history:[]};
 if(present.isSymbolicLink())throw error('INVALID_CONTROL_STORAGE',503);
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||s.nlink!==1||(s.mode&0o077)||s.size>128*1024)throw error('INVALID_CONTROL_STORAGE',503);
 const r=JSON.parse(fs.readFileSync(fd,'utf8'));if(r.schemaVersion!==1||!Number.isSafeInteger(r.revision)||r.revision<1||!Array.isArray(r.history)||r.history.length!==r.revision||r.history.length>100||digest(r.settings)!==r.settingsDigest)throw error('INVALID_CONTROL_STORAGE',503);resolve(r.settings);return r;
 }catch(e){if(e.code?.startsWith('INVALID_'))throw e;throw error('INVALID_CONTROL_STORAGE',503);}finally{fs.closeSync(fd);}
}
export function currentControls(){const r=raw();return {...r,scope:'LOCAL_NON_PRODUCTION_CANDIDATE_ONLY',source:{kind:r.revision?'LOCAL_EXPLICIT_OVERRIDE':'DEMO_DEFAULT','path':'.devsecops/security-view-controls-v1.json',settingsDigest:digest(r.settings)},effectiveConfig:resolve(r.settings)};}
export function writeControls(input,reset=false){
 if(!exact(input,reset?['revision']:['revision','settings'])||!Number.isSafeInteger(input.revision))throw error('INVALID_CONTROL_REQUEST');
 const previous=raw();if(input.revision!==previous.revision)throw error('CONFIG_REVISION_CONFLICT',409);
 if(previous.revision>=100)throw error('CONFIG_HISTORY_BUDGET_EXHAUSTED',429);
 const settings=reset?demoDefaults():structuredClone(input.settings);resolve(settings);
 const now=new Date().toISOString(),revision=previous.revision+1,settingsDigest=digest(settings);
 const record={schemaVersion:1,revision,updatedAt:now,settings,settingsDigest,history:[...previous.history,{revision,at:now,action:reset?'RESTORE_DEMO_DEFAULTS':'SAVE_CANDIDATE_SETTINGS',previousDigest:digest(previous.settings),settingsDigest,settings:structuredClone(settings)}]};
 const dir=parent(),tmp=path.join(dir,'.security-controls-'+randomUUID());let fd;
 try{fd=fs.openSync(tmp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);fs.writeFileSync(fd,JSON.stringify(record,null,2)+'\n');fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(tmp,file);const d=fs.openSync(dir,fs.constants.O_RDONLY);try{fs.fsyncSync(d);}finally{fs.closeSync(d);}}
 finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(tmp))fs.unlinkSync(tmp);}
 return currentControls();
}
