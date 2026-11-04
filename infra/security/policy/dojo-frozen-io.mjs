import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';
// In-memory I/O for frozen existing client validation. Never performs HTTP or host writes.
export function dojoFrozenIO(raw){
 const files=structuredClone(raw.files??{}),requests=[],waits=[],api=structuredClone(raw.api??{}),seen={};let next=1000;
 const tests=structuredClone(raw.tests??[]),queryCounts={};
 const fakeFs={mkdirSync:()=>{if(raw.mkdirError)throw Error('mkdir failed');},existsSync:p=>Object.hasOwn(files,p),readFileSync:(p,encoding)=>{if(!Object.hasOwn(files,p))throw Error('ENOENT: '+p);const v=files[p];if(v?.readError)throw Error('fixture read error');if(v?.virtualLength)return {length:v.virtualLength};const text=typeof v==='string'?v:JSON.stringify(v);return encoding?text:Buffer.from(text);},writeFileSync:(p,v)=>{if(raw.writeErrorPaths?.some(x=>p.includes(x)))throw Error('fixture write failure');files[p]=String(v);}};
 const response=(status,body,invalid=false)=>({status,ok:status>=200&&status<300,json:async()=>{if(invalid)throw Error('Malformed API JSON');return structuredClone(body);},arrayBuffer:async()=>new ArrayBuffer(0)});
 const fetch=async(url,options={})=>{
  const u=new URL(url),p=u.pathname+u.search,method=options.method??'GET';const n=seen[method+' '+p]=(seen[method+' '+p]??0)+1;
  requests.push({method,path:p,form:options.body instanceof FormData?Object.fromEntries([...options.body.entries()].filter(([k])=>k!=='file')):null});
  const fail=api.failures?.find(f=>(!f.method||f.method===method)&&p.includes(f.path)&&(!f.until||n<=f.until));
  if(fail){if(fail.errorName){const error=new Error('Fixture transport failure');error.name=fail.errorName;throw error;}return response(fail.status,fail.body??{},fail.invalidJson);}
  if(p.startsWith('/api/issues/search'))return response(200,raw.sonar??{paging:{total:0},issues:[]});
  if(p.startsWith('/api/v2/products/'))return response(200,{id:raw.target.product});
  if(p.startsWith('/api/v2/tests/'))return response(200,{results:tests,next:api.externalPagination?'https://other.invalid/api/v2/tests/':api.unboundedPagination?url:null});
  if(p.startsWith('/api/v2/import-scan/')||p.startsWith('/api/v2/reimport-scan/')){
   const form=options.body,title=form.get('test_title');let id=Number(form.get('test'))||tests.find(t=>t.title===title)?.id;
   if(!id&&!api.noTestIdentity){id=++next;tests.push({id,title});}
   if(api.noTestIdentity)return response(200,{});
   if(api.identityFromList)return response(200,{});
   return response(200,api.objectIdentity?{test:{id}}:{test:id});
  }
  if(p.startsWith('/api/v2/findings/?')&&u.searchParams.has('test')){
   const id=u.searchParams.get('test');const count=queryCounts[id]=(queryCounts[id]??0)+1;
   let rows=structuredClone(raw.findingsByTest?.[id]??[]);
   if(api.dedupeChanges&&count===2)rows.push({id:999999,active:true,severity:'High'});
   return response(200,{results:rows,next:null});
  }
  if(p.startsWith('/api/v2/findings/?'))return response(200,{results:raw.productFindings??[],next:null});
  if(p.startsWith('/api/v2/findings/')&&method==='PATCH')return response(200,{id:Number(p.split('/').filter(Boolean).at(-1))});
  return response(404,{});
 };
 const clientCode=fs.readFileSync(new URL('../governance/dojo-client.mjs',import.meta.url),'utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
 const context=vm.createContext({fs:fakeFs,crypto,fetch,FormData,Blob,URL,AbortSignal,JSON,Buffer,setTimeout:(fn,ms)=>{waits.push(ms);fn();}});
 const Client=vm.runInContext(clientCode+'\nDojoClient;',context);
 const counts=vm.runInContext('governanceCounts;',context);
 return {fs:fakeFs,Client,counts,fetch,files,requests,waits};
}
