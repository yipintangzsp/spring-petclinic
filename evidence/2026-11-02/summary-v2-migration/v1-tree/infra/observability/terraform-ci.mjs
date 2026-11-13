import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const version='1.17.0';
const zipSha='f32478134ffc6d710eec474bbd316652cdddc0f4e336973a3745e8d3a3309cdf';
const binarySha='aa811293314ba9cdcd7519df5b5dd3c1a28feece1d1390d7844fea039e6f9782';
const addresses=['kubernetes_namespace_v1.lab','kubernetes_resource_quota_v1.budget','kubernetes_config_map_v1.environment'];
export function inspectPlan(plan) {
 const changes=plan.resource_changes??[];
 if(changes.length!==3||changes.some(c=>!addresses.includes(c.address)||JSON.stringify(c.change.actions)!=='["create"]')||new Set(changes.map(c=>c.address)).size!==3)
  throw Error('Only exactly three isolated creates are allowed; preserve any existing state/resources');
 const after=Object.fromEntries(changes.map(c=>[c.address,c.change.after]));
 const ns=after[addresses[0]],quota=after[addresses[1]],cm=after[addresses[2]];
 if(ns.metadata?.[0]?.name!=='tf-devops-lab'||ns.metadata[0].labels?.['petclinic.devops.local/owner']!=='terraform-iac-lab')throw Error('Unexpected namespace ownership');
 if(quota.metadata?.[0]?.name!=='lab-budget'||quota.metadata[0].namespace!=='tf-devops-lab'||cm.metadata?.[0]?.name!=='environment-manifest'||cm.metadata[0].namespace!=='tf-devops-lab')throw Error('Unexpected resource scope');
 const hard=quota.spec?.[0]?.hard;
 for(const k of ['pods','persistentvolumeclaims','secrets','services','requests.storage'])if(hard?.[k]!=='0')throw Error('Pod/storage/secret/service quota must remain zero');
 if(hard.configmaps!=='4'||cm.data?.managed_by!=='terraform'||cm.data.scenario!=='petclinic-devops-study'||cm.data.config_revision!=='v1')throw Error('Unexpected lab settings');
 return changes.map(c=>({address:c.address,actions:c.change.actions}));
}
function hash(file){return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');}
function call(bin,args,options={}) {
 const {expected=[0],...rest}=options;
 const r=spawnSync(bin,args,{encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024,...rest});
 if(r.error||!expected.includes(r.status))throw Error(`${path.basename(bin)} ${args[0]} failed: ${r.error?.message??r.stderr?.slice(-1500)??r.status}`);
 return r;
}
export function cli(home){
 if(process.platform!=='linux'||process.arch!=='arm64')throw Error('This installation is pinned to the existing Linux ARM64 Jenkins');
 const dir=path.join(home,'tools/terraform',version),bin=path.join(dir,'terraform');
 if(fs.existsSync(bin)){if(hash(bin)!==binarySha)throw Error('Cached Terraform digest mismatch; preserve for investigation');return bin;}
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'petclinic-terraform-cli-'));
 try{
  const zip=path.join(temp,'terraform.zip');
  call('curl',['-fSL','--connect-timeout','10','--max-time','180','--retry','2','-o',zip,`https://releases.hashicorp.com/terraform/${version}/terraform_${version}_linux_arm64.zip`],{timeout:200000});
  if(hash(zip)!==zipSha)throw Error('Official pinned archive digest mismatch');
  call('unzip',['-q',zip,'-d',temp]);
  if(hash(path.join(temp,'terraform'))!==binarySha)throw Error('Terraform binary digest mismatch');
  fs.copyFileSync(path.join(temp,'terraform'),bin,fs.constants.COPYFILE_EXCL);fs.chmodSync(bin,0o700);
 }finally{fs.rmSync(temp,{recursive:true});}
 return bin;
}
export function run(){throw Error('Legacy in-Jenkins Terraform execution disabled; use terraform-executor.mjs');}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))run();
