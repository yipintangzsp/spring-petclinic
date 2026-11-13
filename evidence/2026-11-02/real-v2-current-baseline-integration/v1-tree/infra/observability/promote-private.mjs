import {requireSignedRelease} from '../security/gate-contract.mjs';
import {hardenManifest} from '../security/hardening.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export function promoteManifest(original,{image,tag,number,source,time}) {
 if(!/^core\.harbor\.domain\/petclinic\/petclinic@sha256:[a-f0-9]{64}$/.test(image))throw Error('Verified Harbor digest required');
 if(!/^0\.10\.0-ci-\d+$/.test(tag)||String(number)!==tag.split('-ci-')[1]||!/^[a-f0-9]{40}$/.test(source))throw Error('Release identity mismatch');
 const pattern=/^([ \t]*)image:\s+(?:10\.0\.0\.3:30050|core\.harbor\.domain)\/petclinic\/petclinic[:@].*$/gm;
 if([...original.matchAll(pattern)].length!==1)throw Error('Expected one Petclinic image');
 let result=original.replace(pattern,(_,indent)=>`${indent}image: ${image}`);
 for(const [name,value] of Object.entries({APPLICATION_VERSION:tag,BUILD_NUMBER:String(number),BUILD_GIT_COMMIT:source,BUILD_TIME:time})){
  const p=new RegExp(`(name: ${name}\\r?\\n[ \\t]*value:) [^\\r\\n]+`,'g');
  if([...result.matchAll(p)].length!==1)throw Error('Release metadata field missing: '+name);
  result=result.replace(p,(_,prefix)=>`${prefix} '${value}'`);
 }
 return hardenManifest(result);
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 if(!process.env.GITLAB_TOKEN)throw Error('Private GitLab credential required');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'petclinic-promote-'));
 const askpass=path.join(temp,'askpass');
 fs.writeFileSync(askpass,'#!/bin/sh\ncase "$1" in *Username*) printf "%s\\n" oauth2 ;; *) printf "%s\\n" "$GITLAB_TOKEN" ;; esac\n',{mode:0o700});
 const env={...process.env,GIT_ASKPASS:askpass,GIT_TERMINAL_PROMPT:'0'};
 const git=(args)=>{const r=spawnSync('git',args,{env,encoding:'utf8',timeout:60000});if(r.status!==0)throw Error('Private git '+args[0]+' failed; history preserved');return r.stdout.trim();};
 try{
  const remote=git(['remote','get-url','origin']);
  if(remote!=='http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git')throw Error('Refusing promotion outside the private source repository');
  const source=fs.readFileSync('.git-sha','utf8').trim();
  git(['fetch','origin','main']);
  if(git(['rev-parse','origin/main'])!==source)throw Error('Private main changed after this build started');
  git(['checkout','-B','main','origin/main']);
  const built=fs.readFileSync('target/platform/image-digest.txt','utf8').trim();
  const scanned=JSON.parse(fs.readFileSync('target/platform/harbor.json','utf8'));
  if(scanned.digest!==built||scanned.scan_status!=='Success'||scanned.scans?.length!==2)throw Error('Completed runtime scan evidence required');
  if(process.env.K8S_IMAGE!=='core.harbor.domain/petclinic/petclinic@'+built)throw Error('Release image must match verified scan evidence');
  requireSignedRelease({signing:JSON.parse(fs.readFileSync('.devsecops/signing-release.json')),proof:JSON.parse(fs.readFileSync('.devsecops/release-evidence.json')),image:built,source});
  const file='k8s/production/petclinic.yaml';
  const original=fs.readFileSync(file,'utf8');
  const changed=promoteManifest(original,{image:process.env.K8S_IMAGE,tag:process.env.IMAGE_TAG,number:process.env.BUILD_NUMBER,source,time:new Date().toISOString()});
  fs.writeFileSync(file,changed);git(['config','user.name','jenkins-petclinic-ci']);git(['config','user.email','petclinic-ci@devops.local']);git(['add',file]);
  git(['commit','-m',`cd: promote petclinic image to ${process.env.IMAGE_TAG} [skip ci] [ci-skip]`]);
  git(['push','origin','main:main']);
  const revision=git(['rev-parse','HEAD']);
  fs.mkdirSync('target/platform',{recursive:true});
  fs.writeFileSync('target/platform/promotion.json',JSON.stringify({source,revision,image:process.env.K8S_IMAGE,private_repository:remote},null,2));
  console.log('PRIVATE_GIT_PROMOTION=OK '+revision);
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
