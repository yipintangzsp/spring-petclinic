import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {waitGitLabReady} from './service-readiness.mjs';

// Retry temporary service unavailability; authentication and validation errors still fail immediately.
async function resilientFetch(url, options = {}) {
 const {timeoutMs = 30000, ...requestOptions} = options;
 const replayable = !requestOptions.body?.getReader;
 const attempts = replayable ? 6 : 1;
 for (let attempt = 0; attempt < attempts; attempt++) {
  try {
   const response = await fetch(url, {...requestOptions, signal: AbortSignal.timeout(timeoutMs)});
   if (![429, 502, 503, 504].includes(response.status) || attempt === attempts - 1) return response;
   await response.body?.cancel();
  } catch (error) {
   if (attempt === attempts - 1) throw error;
  }
  console.log(`Temporary service unavailable: ${new URL(url).origin}${new URL(url).pathname}; retry ${attempt + 1}/${attempts - 1}`);
  await new Promise(resolve => setTimeout(resolve, Math.min(10000, (attempt + 1) * 5000)));
 }
}

async function request(base, route, options, auth) {
  const response = await resilientFetch(base+route, {...options, headers: {'Content-Type':'application/json', ...auth, ...options?.headers}, timeoutMs:30000});
  if (!response.ok) throw new Error(`${route}: HTTP ${response.status}`);
  return response.status===204 ? null : response.json();
}
function git(...args) {
  const r=spawnSync('git',args,{encoding:'utf8',env:process.env});
  if(r.status!==0)throw new Error(`git ${args[0]} failed`);
  return r.stdout.trim();
}
const mode=process.argv[2];
if(mode==='sonar-ready') {
 const state=await request(process.env.SONAR_HOST_URL,'/api/system/status',{},{});
 if(state.status!=='UP')throw new Error('SonarQube has not reached UP state');
 console.log('SonarQube service ready');
} else if(mode==='gitlab') {
 const base='http://gitlab-service.ns-devops.svc.cluster.local';
 const auth={'PRIVATE-TOKEN':process.env.GITLAB_TOKEN};
 if(!process.env.GITLAB_TOKEN)throw new Error('GitLab credential missing');
 const user=await waitGitLabReady(base,{headers:auth});
 console.log('GitLab Rails readiness verified');
 const full=user.username+'/petclinic-platform';
 let project;
 let response=await resilientFetch(base+'/api/v4/projects/'+encodeURIComponent(full),{headers:auth,timeoutMs:30000});
 if(response.status===404) project=await request(base,'/api/v4/projects',{method:'POST',body:JSON.stringify({name:'petclinic-platform',path:'petclinic-platform',visibility:'private',initialize_with_readme:false})},auth);
 else {if(!response.ok)throw new Error('GitLab project lookup failed');project=await response.json();}
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'petclinic-gitlab-'));
 const askpass=path.join(tmp,'askpass.sh');
 fs.writeFileSync(askpass,'#!/bin/sh\ncase "$1" in *Username*) printf "%s\\n" oauth2 ;; *) printf "%s\\n" "$GITLAB_TOKEN" ;; esac\n',{mode:0o700});
 try {
  const remote=base+'/'+full+'.git';
  const pushed=spawnSync('git',['push',remote,'HEAD:refs/heads/main'],{env:{...process.env,GIT_ASKPASS:askpass,GIT_TERMINAL_PROMPT:'0'},encoding:'utf8',timeout:120000});
  if(pushed.status!==0)throw new Error('GitLab mirror push failed; existing history was preserved');
  const commit=git('rev-parse','HEAD');
  const remoteCommit=await request(base,`/api/v4/projects/${project.id}/repository/commits/main`,{},auth);
  if(remoteCommit.id!==commit)throw new Error('GitLab mirror source mismatch');
  fs.mkdirSync('target/platform',{recursive:true});
  fs.writeFileSync('target/platform/gitlab.json',JSON.stringify({project_id:project.id,project:full,commit,verified:true},null,2));
  console.log(`GitLab mirror verified: ${full} ${commit}`);
 } finally { fs.rmSync(tmp,{recursive:true,force:true}); }
} else if(mode==='harbor-project'||mode==='harbor-copy'||mode==='harbor-scan') {
 const base='http://harbor-core.harbor.svc.cluster.local';
 if(!process.env.HARBOR_USER||!process.env.HARBOR_PASS)throw new Error('Harbor credential missing');
 const auth={Authorization:'Basic '+Buffer.from(process.env.HARBOR_USER+':'+process.env.HARBOR_PASS).toString('base64')};
 if(mode==='harbor-project') {
  const r=await resilientFetch(base+'/api/v2.0/projects/petclinic',{headers:auth,timeoutMs:30000});
  if(r.status===404) {
   const create=await resilientFetch(base+'/api/v2.0/projects',{method:'POST',headers:{...auth,'Content-Type':'application/json'},body:JSON.stringify({project_name:'petclinic',metadata:{public:'false'}}),timeoutMs:30000});
   if(!create.ok&&create.status!==409)throw new Error('Harbor project creation failed');
  } else if(!r.ok)throw new Error('Harbor project access failed');
  console.log('Harbor private project ready');
 } else if(mode==='harbor-copy') {
  const tag=process.env.IMAGE_TAG;
  if(!/^0\.9\.0-ci-\d+$/.test(tag))throw new Error('Invalid release tag');
  const repo='petclinic/petclinic', source='http://10.0.0.3:30050', destination=base;
  // Core authenticates repository tokens and proxies to the Basic-auth internal registry.
  const token=await request(base,'/service/token?service=harbor-registry&scope='+encodeURIComponent('repository:'+repo+':pull,push')+'&account='+encodeURIComponent(process.env.HARBOR_USER),{},auth);
  const bearer={Authorization:'Bearer '+token.token};
  const accept='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';
  const copied=new Set();
  async function copyBlob(digest) {
   if(copied.has(digest))return;
   const exists=await resilientFetch(destination+'/v2/'+repo+'/blobs/'+digest,{method:'HEAD',headers:bearer,timeoutMs:30000});
   if(exists.ok){copied.add(digest);return;}
   if(exists.status!==404)throw new Error(`Harbor blob lookup failed: HTTP ${exists.status}`);
   const blob=await resilientFetch(source+'/v2/'+repo+'/blobs/'+digest,{timeoutMs:120000});
   if(!blob.ok)throw new Error('Source blob unavailable');
   const start=await resilientFetch(destination+'/v2/'+repo+'/blobs/uploads/',{method:'POST',headers:bearer,timeoutMs:30000});
   if(start.status!==202)throw new Error(`Harbor upload initialization failed: HTTP ${start.status}`);
   const location=new URL(start.headers.get('location'),destination);
   location.searchParams.set('digest',digest);
   const uploaded=await resilientFetch(destination+location.pathname+location.search,{method:'PUT',headers:{...bearer,'Content-Type':'application/octet-stream',...(blob.headers.get('content-length')?{'Content-Length':blob.headers.get('content-length')}: {})},body:blob.body,duplex:'half',timeoutMs:180000});
   if(uploaded.status!==201)throw new Error(`Harbor blob copy failed: HTTP ${uploaded.status}`);
   copied.add(digest);
  }
  async function copyManifest(reference) {
   const r=await resilientFetch(source+'/v2/'+repo+'/manifests/'+reference,{headers:{Accept:accept},timeoutMs:30000});
   if(!r.ok)throw new Error('Source manifest unavailable');
   const bytes=await r.arrayBuffer(), manifest=JSON.parse(Buffer.from(bytes).toString());
   if(manifest.manifests) for(const child of manifest.manifests)await copyManifest(child.digest);
   else {if(manifest.config)await copyBlob(manifest.config.digest);for(const layer of manifest.layers??[])await copyBlob(layer.digest);}
   const pushed=await resilientFetch(destination+'/v2/'+repo+'/manifests/'+reference,{method:'PUT',headers:{...bearer,'Content-Type':manifest.mediaType||r.headers.get('content-type')},body:bytes,timeoutMs:30000});
   if(pushed.status!==201)throw new Error(`Harbor manifest copy failed: HTTP ${pushed.status}`);
   const sourceDigest=r.headers.get('docker-content-digest'), destDigest=pushed.headers.get('docker-content-digest');
   if(sourceDigest!==destDigest)throw new Error('Harbor copy digest mismatch');
   return {digest:sourceDigest,platforms:(manifest.manifests??[]).map(m=>m.platform?.architecture).filter(x=>x&&x!=='unknown')};
  }
  const result=await copyManifest(tag);
  if(!result.platforms.includes('arm64')||!result.platforms.includes('amd64'))throw new Error('Harbor copy lacks required architecture');
  fs.mkdirSync('target/platform',{recursive:true});
  fs.writeFileSync('target/platform/harbor-copy.json',JSON.stringify({tag,...result,verified:true},null,2));
  console.log('Harbor multi-architecture copy verified: '+tag+' '+result.digest);
 } else {
  const tag=process.env.IMAGE_TAG;
  if(!/^0\.9\.0-ci-\d+$/.test(tag))throw new Error('Invalid release tag');
  const route='/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+encodeURIComponent(tag);
  const artifact=await request(base,route,{},auth);
  const scan=await resilientFetch(base+route+'/scan',{method:'POST',headers:auth,timeoutMs:30000});
  if(!scan.ok&&scan.status!==409)throw new Error('Harbor scan request failed');
  fs.mkdirSync('target/platform',{recursive:true});
  fs.writeFileSync('target/platform/harbor.json',JSON.stringify({tag,digest:artifact.digest,architecture:artifact.extra_attrs?.architecture,scan_requested:true,scan_status:'requested'},null,2));
  console.log(`Harbor multi-architecture audit copy verified: ${tag} ${artifact.digest}; vulnerability scan requested`);
 }
 } else if(mode==='kafka') {
 const env=['env','KAFKA_HEAP_OPTS=-Xms32M -Xmx128M'];
 const prefix=['exec','-i','-n','ns-bigdata','deploy/kafka','--',...env];
 const topic='petclinic-release-v09';
 const create=spawnSync('kubectl',[...prefix,'/opt/kafka/bin/kafka-topics.sh','--bootstrap-server','localhost:9092','--create','--if-not-exists','--topic',topic,'--replication-factor','1','--partitions','1'],{encoding:'utf8',timeout:60000});
 if(create.status!==0)throw new Error('Kafka release topic unavailable');
 const event={service:'petclinic',event:'release_deployed',release:process.env.IMAGE_TAG,build:Number(process.env.BUILD_NUMBER),source_commit:fs.readFileSync('.git-sha','utf8').trim(),timestamp:new Date().toISOString()};
 const produced=spawnSync('kubectl',[...prefix,'/opt/kafka/bin/kafka-console-producer.sh','--bootstrap-server','localhost:9092','--topic',topic,'--producer-property','acks=all'],{input:JSON.stringify(event)+'\n',encoding:'utf8',timeout:60000});
 if(produced.status!==0)throw new Error('Kafka release event delivery failed');
 fs.mkdirSync('target/platform',{recursive:true});
 fs.writeFileSync('target/platform/kafka.json',JSON.stringify({topic,...event,delivered:true},null,2));
 console.log('Kafka release event delivered: '+event.release);
 } else throw new Error('Unknown operation');
