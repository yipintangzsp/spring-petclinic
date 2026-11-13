// Authorized management bootstrap only. Secret stays outside workspace/artifacts.
import fs from 'node:fs';
const run=JSON.parse(fs.readFileSync('runtime-validation-run.json')).validationRunId,phase=process.argv[2],action=process.argv[3];
if(!/^rf3-\d{8}-[a-f0-9]{6}$/.test(run)||!['scan','sign'].includes(phase)||!['create','verify','delete'].includes(action))throw Error('Explicit validation identity required');
if(!process.env.HARBOR_USER||!process.env.HARBOR_PASS)throw Error('Management binding absent; no identity fallback');
const base='http://harbor-core.harbor.svc.cluster.local',auth='Basic '+Buffer.from(process.env.HARBOR_USER+':'+process.env.HARBOR_PASS).toString('base64'),dir='/tmp/runtime-three-'+run;fs.mkdirSync(dir,{recursive:true,mode:0o700});
const file=dir+'/harbor-'+phase+'.json',ledger=dir+'/harbor-'+phase+'-public.json',out='.devsecops/runtime-controlled/build-'+process.env.BUILD_NUMBER;fs.mkdirSync(out,{recursive:true});
const perms=phase==='scan'?[{resource:'artifact',action:'read'},{resource:'scan',action:'read'},{resource:'scan',action:'create'}]:[{resource:'repository',action:'pull'},{resource:'repository',action:'push'},{resource:'artifact',action:'read'}];
const name=run+'-'+phase;async function request(path,method='GET',body){if(!/^(?:\?page_size=100|\/\d+)?$/.test(path))throw Error('Management path outside robot lifecycle');const r=await fetch(base+'/api/v2.0/robots'+path,{method,headers:{Authorization:auth,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(20000)});const text=await r.text();let data;try{data=JSON.parse(text);}catch{}return {status:r.status,data};}
if(action==='create'){
 if(fs.existsSync(file)||fs.existsSync(ledger))throw Error('Unclean previous validation identity');
 const before=await request('?page_size=100');if(before.status!==200||!Array.isArray(before.data)||before.data.some(r=>r.name.endsWith(name)))throw Error('Cannot prove identity absence');
 const result=await request('','POST',{name,description:'Disposable runtime validation '+run,level:'project',duration:1,disable:false,permissions:[{kind:'project',namespace:'petclinic',access:perms}]});
 if(result.status!==201||!result.data?.id||!result.data.secret){fs.writeFileSync(out+'/robot-create-error.json',JSON.stringify({phase,httpStatus:result.status,responseKeys:Object.keys(result.data??{}),secretStored:false}));throw Error('Minimum validation robot creation rejected');}
 const meta={validationRunId:run,phase,id:result.data.id,name:result.data.name,expiresAt:result.data.expires_at,level:'project',permissions:[{kind:'project',namespace:'petclinic',access:perms}],productionAdmin:false,pushAllowed:phase==='sign',artifactDeleteAllowed:false};
 fs.writeFileSync(ledger,JSON.stringify(meta),{mode:0o600});fs.writeFileSync(file,JSON.stringify({username:result.data.name,password:result.data.secret}),{mode:0o600});fs.writeFileSync(out+'/robot-'+phase+'-created.json',JSON.stringify(meta,null,2));console.log(JSON.stringify({phase,status:'CREATED_MINIMUM_PROJECT_ROBOT',id:meta.id,secretArchived:false}));
}else if(action==='verify'){
 const meta=JSON.parse(fs.readFileSync(ledger));if(meta.validationRunId!==run||meta.phase!==phase)throw Error('Identity context mismatch');const live=await request('/'+meta.id);const normalize=xs=>xs.map(x=>x.resource+':'+x.action).sort().join(',');if(live.status!==200||live.data.level!=='project'||live.data.permissions?.length!==1||live.data.permissions[0].namespace!=='petclinic'||normalize(live.data.permissions[0].access)!==normalize(perms))throw Error('Live robot permissions differ; do not execute');fs.writeFileSync(out+'/robot-'+phase+'-verified.json',JSON.stringify({id:meta.id,name:meta.name,level:live.data.level,permissions:live.data.permissions,liveVerified:true}));console.log(JSON.stringify({id:meta.id,permissionsVerified:true}));
}else{
 const meta=JSON.parse(fs.readFileSync(ledger));if(meta.validationRunId!==run||meta.phase!==phase||!meta.name.endsWith(name))throw Error('Foreign robot preserved');
 const current=await request('/'+meta.id);if(current.status!==200||current.data.name!==meta.name)throw Error('Robot identity changed; no deletion');
 const deleted=await request('/'+meta.id,'DELETE');if(deleted.status!==200&&deleted.status!==204)throw Error('Validation robot deletion failed');const after=await request('/'+meta.id);if(after.status!==404)throw Error('Robot absence not proven');
 fs.rmSync(file);fs.rmSync(ledger);fs.writeFileSync(out+'/robot-'+phase+'-deleted.json',JSON.stringify({id:meta.id,name:meta.name,absent:true,privateCredentialRemoved:!fs.existsSync(file),productionIdentityModified:false}));console.log(JSON.stringify({phase,status:'REMOVED',id:meta.id}));
}
