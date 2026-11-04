// Local definition renderer only. No Jenkins client or deployment operation.
import fs from 'node:fs';import path from 'node:path';import {fileURLToPath,pathToFileURL} from 'node:url';
import {JOB,AGENT,RELEASE,MANAGER_COMMIT,CASES} from './contract.mjs';
import {sha,canonical,fail} from '../../summary-v2/codec.mjs';
const ROOT=fileURLToPath(new URL('../../../../',import.meta.url));
export function releaseManifest(){
 const previous=JSON.parse(fs.readFileSync(path.join(ROOT,'evidence/2026-11-04/security-manager-v2-gitleaks-real/linux-package-retry.json')));
 for(const [p,h] of Object.entries(previous.files))if(sha(fs.readFileSync(path.join(ROOT,p)))!==h)fail('sealed Manager input changed');
 const files={...previous.files};
 for(const p of ['infra/security/manager-v2/ci/contract.mjs','infra/security/manager-v2/ci/entry.mjs'])files[p]=sha(fs.readFileSync(path.join(ROOT,p)));
 return {schemaVersion:1,scope:'GITLEAKS_VALIDATION_ONLY',managerCommit:MANAGER_COMMIT,files};
}
export function pipeline(manifestSha){
 if(!/^[a-f0-9]{64}$/.test(manifestSha))fail('manifest SHA');
 return `// DISABLED job definition. No built-in fallback; no SCM/credentials/publication.
pipeline {
 agent none
 options { skipDefaultCheckout(true); disableConcurrentBuilds(); timeout(time:8, unit:'MINUTES') }
 parameters {
  booleanParam(name:'SECURITY_ENABLED', defaultValue:true)
  choice(name:'GLOBAL_MODE', choices:['audit'])
  choice(name:'SECURITY_LEVEL', choices:['standard'])
  choice(name:'PROFILE', choices:['java-web','python-api'])
  choice(name:'POLICY_VERSION', choices:['baseline-v1'])
  booleanParam(name:'GITLEAKS_ENABLED', defaultValue:true)
  choice(name:'VALIDATION_PROJECT', choices:['java-fixture','python-fixture'])
  string(name:'VALIDATION_RUN_ID', defaultValue:'', description:'Empty derives a bound identity; arbitrary IDs rejected')
  choice(name:'VALIDATION_CASE', choices:${JSON.stringify(Object.keys(CASES))})
 }
 stages {
  stage('Restricted Validation Agent') {
   agent { label '${AGENT}' }
   stages {
    stage('Prepare Private Workspace') { steps { sh 'umask 077; chmod 700 .; test ! -e ci-evidence; test ! -e ci-request.json' } }
    stage('Resolve Fixed Parameters') { steps { script {
     def request=[:]
     ['SECURITY_ENABLED','GLOBAL_MODE','SECURITY_LEVEL','PROFILE','POLICY_VERSION','GITLEAKS_ENABLED','VALIDATION_PROJECT','VALIDATION_RUN_ID','VALIDATION_CASE'].each { key -> request[key]=params[key] }
     writeJSON(file:'ci-request.json', json:request)
    } } }
    stage('Verify Trusted Release and Execute Manager') { steps {
     sh '''#!/bin/sh
set -eu
umask 077
/usr/bin/node --input-type=module <<'NODE'
import fs from 'node:fs';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
const base='${RELEASE}', expected='${manifestSha}';
const stat=p=>{const s=fs.lstatSync(p);if(fs.realpathSync(p)!==p||s.uid!==0||(s.mode&0o022))throw Error('untrusted release boundary');return s;};
for(const p of ['/opt','/opt/security-manager-v2-validation','/opt/security-manager-v2-validation/releases',base])if(!stat(p).isDirectory())throw Error('release directory');
const read=p=>{if(!stat(p).isFile())throw Error('release file');return fs.readFileSync(p);};
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const bytes=read(base+'/manifest.json');if(hash(bytes)!==expected)throw Error('pinned manifest changed');
const manifest=JSON.parse(bytes);
for(const [p,h]of Object.entries(manifest.files)){if(p.startsWith('/')||p.split('/').some(x=>['..','.',''].includes(x))||hash(read(base+'/'+p))!==h)throw Error('release source changed');}
const {spawnSync}=await import('node:child_process');
const result=spawnSync('/usr/bin/node',[base+'/infra/security/manager-v2/ci/entry.mjs'],{stdio:'inherit',env:process.env,timeout:120000});
if(result.status!==0)throw Error('CI validation failed');
NODE
'''
    } }
   }
   post { always { script {
    try { archiveArtifacts(artifacts:'ci-evidence/**', allowEmptyArchive:false, fingerprint:true) }
    finally { deleteDir() }
   } } }
  }
 }
}
`;
}
export function xml(script){
 const escape=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
 return `<?xml version="1.0" encoding="UTF-8"?>\n<flow-definition plugin="workflow-job"><description>OFFLINE CANDIDATE: restricted Agent unavailable; do not enable. No production promotion.</description><keepDependencies>false</keepDependencies><properties/><definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps"><script>${escape(script)}</script><sandbox>true</sandbox></definition><triggers/><disabled>true</disabled></flow-definition>\n`;
}
export function render(directory){
 fs.mkdirSync(directory,{recursive:false,mode:0o700});
 const manifest=canonical(releaseManifest())+'\n',script=pipeline(sha(manifest));
 fs.writeFileSync(path.join(directory,'manifest.json'),manifest,{flag:'wx'});
 fs.writeFileSync(path.join(directory,'Pipeline.groovy'),script,{flag:'wx'});
 fs.writeFileSync(path.join(directory,'job.xml'),xml(script),{flag:'wx'});
 fs.writeFileSync(path.join(directory,'readiness.json'),canonical({job:JOB,requiredAgent:AGENT,enabled:false,imported:false,executionReadiness:'CI_EXECUTION_NOT_READY',release:0,rollout:0})+'\n',{flag:'wx'});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){if(process.argv.length!==3)fail('one new local output directory required');render(path.resolve(process.argv[2]));}
