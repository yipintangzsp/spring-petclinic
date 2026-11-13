// Original DB helper/IO body, with external curl/kubectl/fs effects replaced in memory.
import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';import path from 'node:path';
const source=fs.readFileSync('infra/observability/scanner-db-refresh.mjs','utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ','');
export const dbTime=Date.parse('2026-11-01T00:00:00Z');
export function dbFixture(){
 const metadata=Object.fromEntries([['db',2],['java-db',1]].map(([k,Version])=>[k,{Version,UpdatedAt:'2026-10-31T23:00:00Z',DownloadedAt:'2026-10-31T23:30:00Z',NextUpdate:'2026-11-02T00:00:00Z'}]));
 return {metadata,after:structuredClone(metadata),env:{BUILD_NUMBER:'270',HEAVY_HOLDER:'fixture-holder',PACKAGE_HTTPS_PROXY:'http://synthetic-proxy.invalid:1'},lease:{spec:{holderIdentity:'fixture-holder'}},disk:{time:'2026-11-01T00:00:00Z',capacityBytes:100*1024**3,availableBytes:64*1024**3},ps:'sh',faults:{},io:{},cacheDir:'/home/scanner/.cache/trivy'};
}
export async function replayTrivyDB(input){
 const observations=[],counts={};const next=k=>k+'#'+(counts[k]=(counts[k]??0)+1);
 const manifest=kind=>JSON.stringify({schemaVersion:2,layers:[{mediaType:`application/vnd.aquasec.trivy.${kind==='db'?'db':'javadb'}.layer.v1.tar+gzip`,digest:'sha256:'+'d'.repeat(64),size:128}]});
 let currentKind='db';
 const io=(key)=>{observations.push({type:'io',key});if(input.io[key])throw Error(input.io[key]);};
 const fakeFs={mkdtempSync:()=>{io('mkdtemp');return '/tmp/controlled-db-manifest';},rmSync:()=>io('rm-manifest-temp'),readFileSync:()=>{io('read-manifest-headers');return 'docker-content-digest: '+(input.claimedDigest??'sha256:'+crypto.createHash('sha256').update(input.manifest??manifest(currentKind)).digest('hex'))+'\r\n';}};
 const execFileSync=(bin,args,options={})=>{
  let key,route;
  if(bin==='curl'){const url=args.at(-1);currentKind=url.includes('java-db')?'java-db':'db';route=args.includes('--proxy')?'proxy':'direct';key=url.includes('/token?')?'curl-token':'curl-manifest';}
  else if(bin==='sleep')key='retry-sleep';
  else if(args.includes('lease'))key='lease';
  else if(args.includes('--raw'))key='disk';
  else if(args.includes('ps'))key='ps';
  else if(args.includes('cat')){key='metadata-read';currentKind=args.at(-1).includes('/java-db/')?'java-db':'db';}
  else if(args.includes('rm'))key='cleanup-pidfile';
  else{const script=args.at(-1);key=script.includes('--download-')?'download':script.includes('kill -TERM')?'cleanup-stop':'cleanup-check';if(key==='download')currentKind=script.includes('--download-java-db-only')?'java-db':'db';}
  const tag=next(key),failure=input.faults[tag]??input.faults[key+(route?':'+route:'')]??input.faults[key];observations.push({type:'command',key,occurrence:tag,route,kind:currentKind,bin,args:[...args],timeout:options.timeout,ok:!failure});
  if(failure)throw Error(failure);
  if(key==='curl-token')return input.tokenText??'{"token":"synthetic-public-registry-token"}';
  if(key==='curl-manifest')return input.manifest??manifest(currentKind);
  if(key==='lease')return JSON.stringify(input.lease);
  if(key==='disk')return JSON.stringify({node:{fs:input.disk,runtime:{imageFs:input.disk}}});
  if(key==='ps')return input.ps;
  if(key==='metadata-read')return typeof input.after[currentKind]==='string'?input.after[currentKind]:JSON.stringify(input.after[currentKind]);
  return '';
 };
 class FixedDate extends Date{constructor(...a){super(...(a.length?a:[dbTime]));}static now(){return dbTime;}}
 const context={fs:fakeFs,path,os:{tmpdir:()=>'/tmp'},createHash:crypto.createHash,randomBytes:()=>Buffer.alloc(12,1),execFileSync,process:{env:structuredClone(input.env)},Date:FixedDate,Buffer,structuredClone};
 let exitStatus=0,diagnostic,result;
 try{const api=vm.runInNewContext('(function(){'+source+';return {ensureScannerDatabases,scannerRefreshIO};})()',context);result=await api.ensureScannerDatabases(input.metadata,api.scannerRefreshIO({cacheDir:input.cacheDir}),dbTime);}catch(e){exitStatus=1;diagnostic=e.message;}
 return {schema:1,stage:'database-prerequisite',complete:true,classification:'CONTROLLED_REPLAY',execution:{exitStatus,...(diagnostic?{diagnostic}:{})},observations,metadataBefore:structuredClone(input.metadata),...(result?{result:JSON.parse(JSON.stringify(result))}:{})};
}
