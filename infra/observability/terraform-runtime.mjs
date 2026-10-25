import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {cli} from './terraform-ci.mjs';
import {acceptedProviderPackage} from './terraform-provider-build.mjs';
const root='infra/devops-lab/iac/isolated',repo='petclinic/terraform-runner';
const sha=f=>crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function call(bin,args,options={}){const r=spawnSync(bin,args,{encoding:'utf8',timeout:120000,maxBuffer:4*1024*1024,...options});if(r.status!==0||r.error)throw Error(`${bin} ${args[0]} failed: ${r.error?.message??r.stderr?.slice(-1200)}`);return r.stdout;}
function owned(){const x=JSON.parse(call('kubectl',['-n','data-infra','get','lease','platform-heavy','-o','json']));if(x.spec.holderIdentity!==`jenkins-petclinic-${process.env.BUILD_NUMBER}`)throw Error('Existing release Lease required');}
import {requireZeroVulnerabilities,assessRuntimeVulnerabilities,requireRuntimeVulnerabilityAcceptance} from './terraform-vulnerability-gate.mjs';
export {requireZeroVulnerabilities};
export function renderProviderVersion(source,version){
 if(!/^3\.4\.0-petclinic\.\d+$/.test(version))throw Error('Reviewed custom provider version required');
 if((source.match(/version\s*=\s*"2\.38\.0"/g)??[]).length!==1)throw Error('Original provider configuration changed');
 return source.replace(/(version\s*=\s*)"2\.38\.0"/,'$1"'+version+'"');
}
export function providerLock(version,h1){
 if(!/^3\.4\.0-petclinic\.\d+$/.test(version)||!/^h1:[A-Za-z0-9+/]{43}=$/.test(h1))throw Error('Exact custom package checksum required');
 return '# Locally rebuilt security provider; not an upstream-signed package.\nprovider "registry.terraform.io/hashicorp/kubernetes" {\n version = "'+version+'"\n constraints = "'+version+'"\n hashes = ["'+h1+'"]\n}\n';
}
export async function buildRuntime(){
 owned();const n=process.env.BUILD_NUMBER,home=process.env.JENKINS_HOME;if(!/^\d+$/.test(n??'')||!home)throw Error('Explicit CI context required');
 const providerBuild=JSON.parse(fs.readFileSync('target/platform/terraform-provider-build.json'));
 const terraformBinarySha=sha(cli(home));
 const source=fs.readFileSync('.git-sha','utf8').trim(),tag='isolation-ci-'+n,local='127.0.0.1:13050/'+repo+':'+tag;
 fs.mkdirSync('target/platform',{recursive:true});const context=fs.mkdtempSync('target/tf-runtime-');
 try{
  fs.copyFileSync(cli(home),context+'/terraform');
  const accepted=acceptedProviderPackage(home),version=accepted.r.version;
  const currentBuild=JSON.parse(fs.readFileSync('target/platform/terraform-provider-build.json'));
  if(currentBuild.status!=='success'||currentBuild.source!==source||currentBuild.recipe_sha256!==accepted.key||currentBuild.binary_sha256!==accepted.proof.binary_sha256)throw Error('Matching native provider build required');
  fs.cpSync(accepted.package,context+'/providers/registry.terraform.io/hashicorp/kubernetes/'+version+'/linux_arm64',{recursive:true,dereference:true});
  for(const p of ['worker.py','sandbox.py','terraform.rc','Dockerfile'])fs.copyFileSync(root+'/'+p,context+'/'+p);
  for(const name of ['terraform','remote']){
   const original=fs.readFileSync('infra/devops-lab/iac/'+name+'/main.tf','utf8');
   const rendered=renderProviderVersion(original,version);
   fs.mkdirSync(context+'/source/'+name,{recursive:true});fs.writeFileSync(context+'/source/'+name+'/main.tf',rendered);
   fs.writeFileSync(context+'/source/'+name+'/.terraform.lock.hcl',providerLock(version,accepted.proof.package_h1));
  }
  fs.writeFileSync(context+'/source/.git-sha',source);
  call('docker',['buildx','build','--platform','linux/arm64','--provenance=false','--pull=false','--label','org.opencontainers.image.revision='+source,'--label','petclinic.devops.local/provider-version='+providerBuild.provider_version,'--label','petclinic.devops.local/provider-recipe='+providerBuild.recipe_sha256,'--metadata-file','target/platform/terraform-runtime-build.json','-t',local,'--push',context],{timeout:600000});
 }finally{fs.rmSync(context,{recursive:true,force:true});}
 call('docker',['buildx','prune','--force','--filter','type=source.local']);
 const build=JSON.parse(fs.readFileSync('target/platform/terraform-runtime-build.json'));const digest=build['containerimage.digest'];if(!/^sha256:[a-f0-9]{64}$/.test(digest??''))throw Error('Runtime manifest digest missing');
 const origin='http://'+process.env.REGISTRY_API,base='http://harbor-core.harbor.svc.cluster.local';
 if(!process.env.HARBOR_USER||!process.env.HARBOR_PASS)throw Error('Existing Harbor credential required');
 const auth={Authorization:'Basic '+Buffer.from(process.env.HARBOR_USER+':'+process.env.HARBOR_PASS).toString('base64')};
 async function fetcher(url,opt={}){const response=await fetch(url,{...opt,signal:AbortSignal.timeout(180000)});return response;}
 const tokenResponse=await fetcher(base+'/service/token?service=harbor-registry&scope='+encodeURIComponent('repository:'+repo+':pull,push'),{headers:auth});if(!tokenResponse.ok)throw Error('Harbor runtime repository token unavailable');const bearer={Authorization:'Bearer '+(await tokenResponse.json()).token};
 const accept={'Accept':'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'};
 const m=await fetcher(origin+'/v2/'+repo+'/manifests/'+tag,{headers:accept});if(!m.ok||m.headers.get('docker-content-digest')!==digest)throw Error('Runtime source digest mismatch');const bytes=Buffer.from(await m.arrayBuffer());if('sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')!==digest)throw Error('Runtime manifest bytes mismatch');const manifest=JSON.parse(bytes);
 if(manifest.manifests||!manifest.config||!manifest.layers)throw Error('Pinned runtime must be one native ARM64 manifest');
 for(const blob of [manifest.config,...manifest.layers]){
  const check=await fetcher(base+'/v2/'+repo+'/blobs/'+blob.digest,{method:'HEAD',headers:bearer});if(check.ok)continue;if(check.status!==404)throw Error('Harbor blob metadata unavailable');
  const original=await fetcher(origin+'/v2/'+repo+'/blobs/'+blob.digest);if(!original.ok)throw Error('Runtime blob missing');
  const start=await fetcher(base+'/v2/'+repo+'/blobs/uploads/',{method:'POST',headers:bearer});if(start.status!==202)throw Error('Runtime upload initialization failed');const url=new URL(start.headers.get('location'),base);url.searchParams.set('digest',blob.digest);
  const copied=await fetcher(base+url.pathname+url.search,{method:'PUT',headers:{...bearer,'Content-Type':'application/octet-stream',...(original.headers.get('content-length')?{'Content-Length':original.headers.get('content-length')}: {})},body:original.body,duplex:'half'});if(copied.status!==201)throw Error('Harbor rejected runtime blob digest');
 }
 const push=await fetcher(base+'/v2/'+repo+'/manifests/'+tag,{method:'PUT',headers:{...bearer,'Content-Type':manifest.mediaType},body:bytes});if(push.status!==201||push.headers.get('docker-content-digest')!==digest)throw Error('Harbor runtime manifest mismatch');
 const route=base+'/api/v2.0/projects/petclinic/repositories/terraform-runner/artifacts/'+encodeURIComponent(digest);
 let artifact;
 for(let i=0;i<20;i++){const x=await fetcher(route+'?with_scan_overview=true',{headers:auth});if(x.ok){artifact=await x.json();break;}if(x.status!==404)throw Error('Harbor runtime registration failed');await sleep(1000);}
 if(artifact?.digest!==digest)throw Error('Runtime artifact registration mismatch');
 const request=await fetcher(route+'/scan',{method:'POST',headers:auth});if(!request.ok&&request.status!==409)throw Error('Runtime vulnerability scan request rejected');
 let scan;
 for(let i=0;i<120;i++){const x=await fetcher(route+'?with_scan_overview=true',{headers:auth});if(!x.ok)throw Error('Runtime scan status unavailable');const a=await x.json();scan=Object.values(a.scan_overview??{}).find(v=>v.scan_status);if(scan?.scan_status==='Success')break;if(['Error','Stopped'].includes(scan?.scan_status))throw Error('Runtime scan failed');console.log('Terraform runtime scan: '+(scan?.scan_status??'pending'));await sleep(5000);}
 if(scan?.scan_status!=='Success')throw Error('Runtime scan timeout');
 const configResponse=await fetcher(origin+'/v2/'+repo+'/blobs/'+manifest.config.digest);const config=await configResponse.json();if(config.architecture!=='arm64'||config.os!=='linux'||config.config?.Labels?.['org.opencontainers.image.revision']!==source||config.config?.Labels?.['petclinic.devops.local/provider-version']!==providerBuild.provider_version||config.config?.Labels?.['petclinic.devops.local/provider-recipe']!==providerBuild.recipe_sha256)throw Error('Runtime architecture/source mismatch');
 const report={status:'success',source,tag,digest,terraform_binary_sha256:terraformBinarySha,image:'127.0.0.1:30050/'+repo+'@'+digest,harbor_image:'core.harbor.domain/'+repo+'@'+digest,architecture:'arm64',scan,source_labels:config.config.Labels,offline_provider:true,terraform_version:'1.17.0',provider_version:providerBuild.provider_version,provider_binary_sha256:providerBuild.binary_sha256,provider_build_recipe_sha256:providerBuild.recipe_sha256,provider_package_h1:providerBuild.package_h1};
 try{
  if(scan.summary?.total!==0){
   const raw=await fetcher(route+'/additions/vulnerabilities',{headers:{...auth,Accept:'application/vnd.security.vulnerability.report; version=1.1, application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0'}});
   if(!raw.ok)throw Error('Original detailed vulnerability report unavailable');
   report.raw_vulnerability_report=await raw.json();
   fs.writeFileSync('target/platform/terraform-runtime-vulnerabilities-raw.json',JSON.stringify(report.raw_vulnerability_report,null,2));
  }
  report.vulnerability_assessment=assessRuntimeVulnerabilities(scan,report.raw_vulnerability_report,terraformBinarySha);
  report.zero_vulnerability_gate=report.vulnerability_assessment.status;
  requireRuntimeVulnerabilityAcceptance(report);
 }catch(error){report.status='failed';report.zero_vulnerability_gate='failed';report.error=error.message;fs.writeFileSync('target/platform/terraform-runtime.json',JSON.stringify(report,null,2));throw error;}
 fs.writeFileSync('target/platform/terraform-runtime.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))buildRuntime().catch(e=>{console.error(e.message);process.exitCode=1;});
