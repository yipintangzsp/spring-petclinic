pipeline {
 agent none
 options { skipDefaultCheckout(true); disableConcurrentBuilds(); disableRestartFromStage(); timeout(time: 3, unit: 'MINUTES') }
 stages {
  stage('Verify GitLab Webhook') {
   steps { script {
    def causes=currentBuild.getBuildCauses('com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause')
    if(causes.size()!=1 || env.gitlabActionType!='PUSH' || env.gitlabSourceBranch!='security-demo/gitlab-push-20261105' || env.gitlabSourceRepoHttpUrl!='@SOURCE_REPOSITORY@' || env.gitlabAfter!='@COMMIT@') {error('Fixed real webhook identity required')}
    currentBuild.description='Manager CI / '+env.gitlabAfter
    echo 'WEBHOOK_COMMIT_ACCEPTED '+env.gitlabAfter
   } }
  }
  stage('Security Manager Standard Intake') {
   agent { label 'built-in' }
   steps { script { dir("manager-ci-${env.BUILD_NUMBER}") {
    try {
     withCredentials([sshUserPrivateKey(credentialsId:'security-gitleaks-demo-ssh',keyFileVariable:'CI_SSH_KEY')]) {
      sh label:'Fixed Manager CI request over restricted SSH',script:'''#!/bin/sh
set +x
set -eu
umask 077
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C CI_SSH_KEY="$CI_SSH_KEY" CI_JOB="$JOB_NAME" CI_BUILD="$BUILD_NUMBER" /usr/bin/node --max-old-space-size=64 --input-type=module <<'NODE'
import fs from 'node:fs';import path from 'node:path';import {execFileSync}from'node:child_process';
if(process.env.CI_JOB!=='security-gitlab-push-demo'||process.env.CI_BUILD!=='@BUILD_ID@')throw Error('CI_IDENTITY_REJECTED');
const key=process.env.CI_SSH_KEY,st=fs.lstatSync(key);if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o077))throw Error('KEY_BOUNDARY');
fs.mkdirSync('evidence',{mode:0o700});fs.writeFileSync('known_hosts','192.168.1.58 ssh-ed25519 @HOST_KEY@'+String.fromCharCode(10),{flag:'wx',mode:0o400});
const v={projectId:'python-fixture',sourceRepository:'http://gitlab.devops.local/root/petclinic-platform.git',commitSha:'@COMMIT@',ciProvider:'jenkins',jobId:process.env.CI_JOB,buildId:Number(process.env.CI_BUILD),trigger:'gitlab-webhook',pluginId:'gitleaks',scenarioId:'clean'};
const args=['-F','/dev/null','-T','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','UserKnownHostsFile='+path.resolve('known_hosts'),'-o','GlobalKnownHostsFile=/dev/null','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','security-gitleaks@192.168.64.11','manager-ci-v1'];
let text,status=0;try{text=execFileSync('/usr/bin/ssh',args,{input:JSON.stringify(v),encoding:'utf8',timeout:110000,maxBuffer:16384,env:{PATH:'/usr/bin:/bin',LANG:'C'}});}catch(e){text=e.stdout||'{"error":"CI_TRANSPORT_ERROR"}';status=1;}
const result=JSON.parse(text);fs.writeFileSync('evidence/security-manager-result.json',JSON.stringify(result,null,2),{flag:'wx',mode:0o400});console.log(JSON.stringify({runId:result.runId,state:result.state,policyDecision:result.policyDecision,resultDigest:result.resultDigest}));if(result.state!=='COMPLETED'||result.evidenceClass!=='REAL'||result.evaluationCount!==1||!['PASS','FAIL'].includes(result.policyDecision))process.exit(1);
NODE
'''
     }
     def r=readJSON file:'evidence/security-manager-result.json',returnPojo:true
     if(r.ciContext.commitSha!='@COMMIT@' || r.ciContext.buildId.toString()!=env.BUILD_NUMBER || r.projectId!='python-fixture')error('Manager CI result binding failed')
     env.SECURITY_POLICY=r.policyDecision
     env.SECURITY_RUN=r.runId
    } finally {if(fileExists('evidence/security-manager-result.json')){archiveArtifacts artifacts:'evidence/*.json',allowEmptyArchive:false};deleteDir()}
   } } }
  }
  stage('Policy Gate') {steps {script {if(env.SECURITY_POLICY!='PASS')error('Security Manager Policy '+env.SECURITY_POLICY);echo 'POLICY_GATE_PASS '+env.SECURITY_RUN}}}
  stage('Demo Publish') {steps {echo 'NO_SIDE_EFFECT_DEMO_ONLY: no image, GitOps or deployment operation'}}
 }
}
