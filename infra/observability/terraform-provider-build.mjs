import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const security='infra/devops-lab/iac/isolated/security';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export function fileSha(p) {
 const h=crypto.createHash('sha256'),fd=fs.openSync(p,'r'),b=Buffer.alloc(1024*1024);
 try{let n;while((n=fs.readSync(fd,b,0,b.length,null))>0)h.update(b.subarray(0,n));}finally{fs.closeSync(fd);}
 return h.digest('hex');
}
export function hasUnmaintainedOpenpgpPath(p) {
 const needle=Buffer.from('golang.org/x/crypto/openpgp'),fd=fs.openSync(p,'r'),b=Buffer.alloc(1024*1024);let tail=Buffer.alloc(0);
 try{let n;while((n=fs.readSync(fd,b,0,b.length,null))>0){const part=Buffer.concat([tail,b.subarray(0,n)]);if(part.includes(needle))return true;tail=part.subarray(Math.max(0,part.length-needle.length+1));}return false;}finally{fs.closeSync(fd);}
}
function call(bin,args,options={}) {
 const r=spawnSync(bin,args,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024,...options});
 if(r.status!==0||r.error)throw Error(`${bin} ${args[0]} failed: ${r.error?.message??r.stderr?.slice(-1200)}`);
 return r.stdout.trim();
}
export function validateRecipe(r) {
 if(r.schema_version!==1||!/^3\.4\.0-petclinic\.\d+$/.test(r.version)||r.go_version!=='go1.27.3')throw Error('Explicit supported custom provider recipe required');
 if(!/^python@sha256:[a-f0-9]{64}$/.test(r.builder_image))throw Error('Pinned builder required');
 const bounds={cpu:1,memory_mib:1536,pids:128,timeout_seconds:900,scratch_mib:3072};if(!r.limits||Object.keys(r.limits).length!==Object.keys(bounds).length||Object.entries(bounds).some(([k,v])=>r.limits[k]!==v))throw Error('Fixed builder resource bounds required');
 if(JSON.stringify(r.build_flags)!==JSON.stringify(['-mod=vendor','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=']))throw Error('Fixed reproducible build flags required');
 if(r.source_archive_root!=='terraform-provider-kubernetes-3.4.0'||r.upstream_version!=='3.4.0')throw Error('Fixed upstream source required');
 const names=Object.keys(r.inputs??{}).sort();
 if(JSON.stringify(names)!==JSON.stringify(['go1.27.3.linux-arm64.tar.gz','provider-source.tar.gz','provider-vendor.tar.gz']))throw Error('Unexpected build inputs');
 for(const x of Object.values(r.inputs))if(!/^[a-f0-9]{64}$/.test(x.sha256)||!Number.isSafeInteger(x.bytes)||x.bytes<=0||x.bytes>128*1024**2)throw Error('Input digest/size required');
 if(r.vendor_validation?.status!=='success'||!Array.isArray(r.vendor_validation.errors)||r.vendor_validation.errors.length||!Number.isInteger(r.vendor_validation.vendor_files_checked_against_original_module_zips)||r.vendor_validation.vendor_files_checked_against_original_module_zips<=0||!r.custom_build_not_upstream_signed_binary)throw Error('Verified vendor provenance required');
 return r;
}
export function packageHash(directory) {
 const names=fs.readdirSync(directory).sort();
 if(names.length!==2||!names.includes('LICENSE.txt')||!names.some(n=>/^terraform-provider-kubernetes_v3\.4\.0-petclinic\.\d+_x5$/.test(n)))throw Error('Unexpected provider package contents');
 let text='';for(const n of names){const p=path.join(directory,n);if(!fs.lstatSync(p).isFile())throw Error('Unexpected provider package type');text+=fileSha(p)+'  '+n+'\n';}
 return 'h1:'+crypto.createHash('sha256').update(text).digest('base64');
}
export function inputKey(inputs){return sha(Object.keys(inputs).sort().map(n=>`${n} ${inputs[n].sha256} ${inputs[n].bytes}\n`).join(''));}
export function loadRecipe(home=process.env.JENKINS_HOME) {
 if(!home)throw Error('Existing Jenkins tool cache required');
 const raw=fs.readFileSync(security+'/provider-build.json');const r=validateRecipe(JSON.parse(raw));
 if(fileSha(security+'/provider-security.patch')!==r.patch_sha256)throw Error('Reviewed provider patch differs');
 const key=sha(Buffer.concat([raw,fs.readFileSync(security+'/provider-security.patch'),fs.readFileSync(security+'/extract.py'),fs.readFileSync(fileURLToPath(import.meta.url))]));
 const inputsKey=inputKey(r.inputs);
 return {r,key,inputs:path.join(home,'tools/terraform/security-inputs',inputsKey),artifact:path.join(home,'tools/terraform/security-providers',key),filename:`terraform-provider-kubernetes_v${r.version}_x5`};
}
function checkInputs(ctx) {
 for(const [name,x] of Object.entries(ctx.r.inputs)){const p=path.join(ctx.inputs,name);if(!fs.existsSync(p)||fs.statSync(p).size!==x.bytes||fileSha(p)!==x.sha256)throw Error('Verified build input missing or changed: '+name);}
}
export function acceptedProviderPackage(home) {
 const c=loadRecipe(home),proof=JSON.parse(fs.readFileSync(c.artifact+'/build.json'));
 if(proof.status!=='success'||proof.recipe_sha256!==c.key||proof.unit_tests_exit!==0||!proof.independent_builds_equal||!proof.owned_container_removed)throw Error('Native CI provider acceptance missing');
 const pkg=c.artifact+'/package';
 if(proof.unmaintained_openpgp_path_present!==false||hasUnmaintainedOpenpgpPath(pkg+'/'+c.filename)||fileSha(pkg+'/'+c.filename)!==proof.binary_sha256||packageHash(pkg)!==proof.package_h1)throw Error('Cached provider package differs');
 return {...c,package:pkg,proof};
}
function requireLease(build) {
 const x=JSON.parse(call('kubectl',['-n','data-infra','get','lease','platform-heavy','-o','json']));
 if(x.spec.holderIdentity!==`jenkins-petclinic-${build}`)throw Error('Existing outer release Lease required; do not acquire a second lock');
}
function dockerBase(c,work,extra=[]) {
 return ['--network','none','--read-only','--user',`${process.getuid()}:${process.getgid()}`,'--cpus','1','--memory','1536m','--memory-swap','1536m','--pids-limit','128','--cap-drop','ALL','--security-opt','no-new-privileges','--security-opt','apparmor=docker-default','--label','petclinic.devops.local/owner=terraform-provider-build','--label','petclinic.devops.local/job='+process.env.JOB_NAME,'--label','petclinic.devops.local/build='+process.env.BUILD_NUMBER,'--label','petclinic.devops.local/source='+fs.readFileSync('.git-sha','utf8').trim(),...extra,'--mount',`type=bind,src=${work},dst=/work`];
}
function unpack(c,archive,out) {
 fs.mkdirSync(out,{recursive:true,mode:0o700});
 const args=['run','--rm',...dockerBase(c,out), '--mount',`type=bind,src=${c.inputs},dst=/inputs,readonly`,'--mount',`type=bind,src=${path.resolve(security+'/extract.py')},dst=/extract.py,readonly`, '--entrypoint','/usr/bin/timeout',c.r.builder_image,'--signal=TERM','--kill-after=5s','105s','python3','/extract.py','/inputs/'+archive,'/work',c.r.inputs[archive].sha256];
 call('docker',args,{timeout:120000});
}
export async function buildProvider() {
 const build=process.env.BUILD_NUMBER;if(process.env.JOB_NAME!=='petclinic-ci'||process.getuid()===0)throw Error('Non-root petclinic-ci executor required');if(!/^\d+$/.test(build??''))throw Error('Explicit CI build required');requireLease(build);
 if(call('docker',['ps','--filter','label=petclinic.devops.local/owner=terraform-provider-build','--format','{{.ID}}']))throw Error('Existing active provider build preserved');
 fs.mkdirSync('target/platform',{recursive:true});
 try{const c=acceptedProviderPackage();fs.writeFileSync('target/platform/terraform-provider-build.json',JSON.stringify({...c.proof,artifact_built_from_source:c.proof.source,source:fs.readFileSync('.git-sha','utf8').trim(),cache_hit:true,reused_native_build_metrics:true},null,2));console.log('Verified native provider cache '+c.key);return;}catch(error){console.log('Native provider rebuild required: '+error.message);}
 const c=loadRecipe();checkInputs(c);if(!['aarch64','arm64'].includes(call('docker',['info','--format','{{.Architecture}}'])))throw Error('Native ARM64 Docker builder required');call('docker',['image','inspect',c.r.builder_image]);if(fs.existsSync(c.artifact))fs.renameSync(c.artifact,c.artifact+'.rejected-'+crypto.randomBytes(4).toString('hex'));const home=process.env.JENKINS_HOME;
 const work=fs.mkdtempSync(path.join(home,'tools/terraform/provider-build-'));let id,stopped=false,report={status:'failed',recipe_sha256:c.key,provider_version:c.r.version,source:fs.readFileSync('.git-sha','utf8').trim(),cache_hit:false};
 const owner={build,job:process.env.JOB_NAME,source:report.source,basename:path.basename(work),nonce:crypto.randomBytes(16).toString('hex')};fs.writeFileSync(work+'/.build-owner.json',JSON.stringify(owner));fs.writeFileSync('target/platform/terraform-provider-build-owner.json',JSON.stringify(owner));
 const logFile='target/platform/terraform-provider-build.log';
 function ownedInspect(){const x=JSON.parse(call('docker',['inspect',id]))[0];if(x.Id!==id||x.Config.Labels?.['petclinic.devops.local/owner']!=='terraform-provider-build'||x.Config.Labels?.['petclinic.devops.local/build']!==build||x.Config.Labels?.['petclinic.devops.local/job']!==process.env.JOB_NAME||x.Config.Labels?.['petclinic.devops.local/source']!==report.source)throw Error('Foreign build container preserved');return x;}
 function stop(){if(id&&!stopped){const x=ownedInspect();if(x.State.Running)call('docker',['stop','--time','5',id],{timeout:15000});stopped=true;}}
 try {
  unpack(c,'provider-source.tar.gz',work);const src=path.join(work,c.r.source_archive_root);unpack(c,'provider-vendor.tar.gz',src);
  call('git',['-C',src,'apply','--check',path.resolve(security+'/provider-security.patch')]);call('git',['-C',src,'apply',path.resolve(security+'/provider-security.patch')]);
  if(fileSha(src+'/go.mod')!==c.r.go_mod_sha256||fileSha(src+'/go.sum')!==c.r.go_sum_sha256)throw Error('Patched dependency locks differ');
  unpack(c,'go1.27.3.linux-arm64.tar.gz',work+'/sdk');const sdk=work+'/sdk/go';
  fs.mkdirSync(work+'/scratch');fs.mkdirSync(work+'/scratch/result');fs.mkdirSync(work+'/scratch/cache');fs.mkdirSync(work+'/scratch/tmp');
  const script=`set -eu
export PATH=/opt/go/bin:/usr/local/bin:/usr/bin:/bin GOTOOLCHAIN=local GOTELEMETRY=off GOWORK=off GOPROXY=off GOSUMDB=sum.golang.org GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOMAXPROCS=1 GOMEMLIMIT=768MiB GOCACHE=/work/cache GOTMPDIR=/work/tmp HOME=/work
[ "$(go version)" = "go version go1.27.3 linux/arm64" ]
cd /src
go test -mod=vendor -p=1 ./manifest/openapi
go build -p=1 -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /work/result/a .
# A second empty compiler cache forces a genuinely independent rebuild.
rm -rf -- /work/cache
mkdir -p /work/cache
go build -p=1 -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /work/result/b .
python3 -c 'import hashlib,json,pathlib; p=pathlib.Path("/work/result"); a=hashlib.file_digest((p/"a").open("rb"),"sha256").hexdigest(); b=hashlib.file_digest((p/"b").open("rb"),"sha256").hexdigest(); assert a==b; (p/"metrics.json").write_text(json.dumps({"binary_sha256":a,"independent_builds_equal":True,"memory_peak_bytes":int(pathlib.Path("/sys/fs/cgroup/memory.peak").read_text()),"cpu_stat":pathlib.Path("/sys/fs/cgroup/cpu.stat").read_text()}))'
`;
  id=call('docker',['create',...dockerBase(c,work+'/scratch',['--label','petclinic.devops.local/build='+build]),'--mount',`type=bind,src=${src},dst=/src,readonly`,'--mount',`type=bind,src=${sdk},dst=/opt/go,readonly`,'--entrypoint','/usr/bin/timeout',c.r.builder_image,'--signal=TERM','--kill-after=5s','880s','/bin/sh','-c',script]);
  if(!/^[a-f0-9]{64}$/.test(id))throw Error('Container ID missing');
  const observed=ownedInspect(),hc=observed.HostConfig;
  if(!hc.ReadonlyRootfs||hc.Privileged||hc.NetworkMode!=='none'||hc.PidMode==='host'||hc.IpcMode==='host'||hc.Memory!==1536*1024**2||hc.MemorySwap!==1536*1024**2||hc.NanoCpus!==1e9||hc.PidsLimit!==128||!hc.CapDrop?.some(x=>['ALL','CAP_ALL'].includes(x))||!hc.SecurityOpt?.some(x=>x.startsWith('no-new-privileges'))||observed.AppArmorProfile!=='docker-default'||observed.Mounts.some(m=>m.RW&&m.Destination!=='/work')||observed.Config.User!==`${process.getuid()}:${process.getgid()}`||observed.Config.Env.some(e=>/^(.*TOKEN|.*PASSWORD|.*SECRET|KUBE_.*|HARBOR_.*)=/.test(e)))throw Error('Observed build container isolation or limits differ');
  report.observed_confinement={uid:observed.Config.User,network:hc.NetworkMode,read_only_root:hc.ReadonlyRootfs,cap_drop:hc.CapDrop,apparmor:observed.AppArmorProfile,no_new_privileges:true,memory_bytes:hc.Memory,memory_and_swap_bytes:hc.MemorySwap,nano_cpus:hc.NanoCpus,pids_limit:hc.PidsLimit};

  const fd=fs.openSync(logFile,'w');let timer,guard,error;
  try{await new Promise((resolve,reject)=>{const child=spawn('docker',['start','-a',id],{stdio:['ignore',fd,fd]});timer=setTimeout(()=>{error=Error('Provider build timeout');try{stop();}catch(e){error=e;}},c.r.limits.timeout_seconds*1000);guard=setInterval(()=>{try{requireLease(build);const used=Number(call('du',['-sm',work]).split(/\s/)[0]);report.scratch_peak_mib=Math.max(report.scratch_peak_mib??0,used);if(used>c.r.limits.scratch_mib)throw Error('Provider scratch budget exceeded');}catch(e){error=e;try{stop();}catch(e2){error=e2;}}},5000);child.once('error',reject);child.once('exit',code=>code===0&&!error?resolve():reject(error??Error('Native provider build failed: '+code)));});}finally{clearTimeout(timer);clearInterval(guard);fs.closeSync(fd);}
  const x=ownedInspect();report.container={id,exit:x.State.ExitCode,oom_killed:x.State.OOMKilled,started_at:x.State.StartedAt,finished_at:x.State.FinishedAt,limits:c.r.limits};
  if(x.State.ExitCode!==0||x.State.OOMKilled)throw Error('Provider build did not complete normally');
  if(hasUnmaintainedOpenpgpPath(work+'/scratch/result/a'))throw Error('Unmaintained OpenPGP package present in rebuilt provider');
  const metrics=JSON.parse(fs.readFileSync(work+'/scratch/result/metrics.json'));if(!metrics.independent_builds_equal||!(metrics.memory_peak_bytes>0))throw Error('Build proof missing');
  fs.mkdirSync(c.artifact,{recursive:true,mode:0o700});const pkg=c.artifact+'/package';fs.mkdirSync(pkg,{mode:0o700});fs.copyFileSync(work+'/scratch/result/a',pkg+'/'+c.filename);fs.chmodSync(pkg+'/'+c.filename,0o555);fs.copyFileSync(src+'/LICENSE',pkg+'/LICENSE.txt');
  report={...report,...metrics,status:'success',unit_tests_exit:0,unmaintained_openpgp_path_present:false,package_h1:packageHash(pkg),go_version:c.r.go_version,inputs:c.r.inputs,patch_sha256:c.r.patch_sha256};
  // Cache is accepted only after owned container cleanup below.
 }catch(error){report.error=error.message;throw error;}finally{
  let cleanupError;
  try{if(id){stop();const x=ownedInspect();report.container??={id,exit:x.State.ExitCode,oom_killed:x.State.OOMKilled,started_at:x.State.StartedAt,finished_at:x.State.FinishedAt,limits:c.r.limits};if(x.State.Running)throw Error('Owned build container still running');call('docker',['rm',id]);report.owned_container_removed=true;}}catch(error){cleanupError=error;report.status='failed';report.cleanup_error=error.message;}
  if(!cleanupError)fs.rmSync(work,{recursive:true,force:true});
  fs.writeFileSync('target/platform/terraform-provider-build.json',JSON.stringify(report,null,2));
  if(report.status==='success'&&report.owned_container_removed)fs.writeFileSync(c.artifact+'/build.json',JSON.stringify(report,null,2));
  if(cleanupError)throw cleanupError;
 }

 console.log(JSON.stringify(report,null,2));
}
export function cleanupProviderBuild() {
 const build=process.env.BUILD_NUMBER,job=process.env.JOB_NAME,source=fs.readFileSync('.git-sha','utf8').trim();
 if(!/^\d+$/.test(build??'')||job!=='petclinic-ci'||!/^[a-f0-9]{40}$/.test(source))throw Error('Exact cleanup identity required');
 const labels={'petclinic.devops.local/owner':'terraform-provider-build','petclinic.devops.local/job':job,'petclinic.devops.local/build':build,'petclinic.devops.local/source':source};
 const ids=call('docker',['ps','-aq','--no-trunc',...Object.entries(labels).flatMap(([k,v])=>['--filter',`label=${k}=${v}`])]).split(/\s+/).filter(Boolean),removed=[];
 for(const id of ids){
  const x=JSON.parse(call('docker',['inspect',id]))[0];if(x.Id!==id||Object.entries(labels).some(([k,v])=>x.Config.Labels?.[k]!==v))throw Error('Foreign container preserved');
  if(x.State.Running)call('docker',['stop','--time','5',id],{timeout:15000});
  const now=JSON.parse(call('docker',['inspect',id]))[0];if(now.State.Running||now.Id!==id)throw Error('Owned container did not stop');
  call('docker',['rm',id]);removed.push({id,exit:now.State.ExitCode,oom_killed:now.State.OOMKilled});
 }
 const receipt='target/platform/terraform-provider-build-owner.json';let workRemoved=false;
 if(fs.existsSync(receipt)){
  const r=JSON.parse(fs.readFileSync(receipt));
  if(r.build!==build||r.job!==job||r.source!==source||!/^provider-build-[a-zA-Z0-9]+$/.test(r.basename)||!/^[a-f0-9]{32}$/.test(r.nonce))throw Error('Cleanup receipt changed');
  const work=path.join(process.env.JENKINS_HOME,'tools/terraform',r.basename);
  if(fs.existsSync(work)){
   if(fs.lstatSync(work).isSymbolicLink()||fs.readFileSync(work+'/.build-owner.json','utf8')!==JSON.stringify(r))throw Error('Owned build work directory changed');
   const metrics=work+'/scratch/result/metrics.json';if(fs.existsSync(metrics)&&fs.statSync(metrics).size<1048576)fs.copyFileSync(metrics,'target/platform/terraform-provider-interrupted-metrics.json');
   fs.rmSync(work,{recursive:true,force:true});workRemoved=true;
  }
 }
 fs.mkdirSync('target/platform',{recursive:true});fs.writeFileSync('target/platform/terraform-provider-cleanup.json',JSON.stringify({status:'success',build,source,containers_removed:removed,owned_work_directory_removed:workRemoved},null,2));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{if(process.argv[2]==='cleanup')cleanupProviderBuild();else await buildProvider();}catch(e){console.error(e.message);process.exitCode=1;}}
