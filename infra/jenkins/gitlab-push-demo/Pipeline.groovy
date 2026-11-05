// Fixed trusted dispatcher. No repository execution or publication; server-side forced SSH command enforces scanner scope.
pipeline {
  agent none
  options {
    skipDefaultCheckout(true)
    disableConcurrentBuilds()
    disableRestartFromStage()
    timeout(time: 4, unit: 'MINUTES')
  }
  stages {
    stage('Verify GitLab Push Identity') {
      steps {
        script {
          def causes = currentBuild.getBuildCauses('com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause')
          if (causes.size() != 1) { error('Only a real GitLab webhook cause is accepted') }
          // Installed plugin does not export cause.data to the Pipeline JSON wrapper.
          // Authenticate the original hook and pin its actual repository, branch and commit.
          if (env.gitlabSourceRepoHttpUrl != '@EXPECTED_REPOSITORY@' ||
              env.gitlabActionType != 'PUSH' ||
              env.gitlabSourceBranch != 'security-demo/gitlab-push-20261105' ||
              env.gitlabAfter != '@EXPECTED_COMMIT@') {
            error('Unexpected project, event, fixed branch or commit')
          }
          currentBuild.description = 'GitLab Push / project 12 / ' + env.gitlabAfter
          echo 'GITLAB_PUSH_ACCEPTED project=12 branch=security-demo/gitlab-push-20261105 commit=' + env.gitlabAfter
        }
      }
    }
    stage('Restricted Gitleaks and Policy Gate') {
      agent { label 'built-in' }
      steps {
        script {
          dir("gitleaks-clean-${env.BUILD_NUMBER}") {
            try {
              writeFile file: 'trusted-package.b64', text: @TRUSTED_PACKAGE_CHUNKS@
              withCredentials([sshUserPrivateKey(credentialsId: 'security-gitleaks-demo-ssh',
                  keyFileVariable: 'DEMO_SSH_KEY')]) {
                sh label: 'Invoke fixed Clean over restricted SSH', script: '''#!/bin/sh
set +x
set -eu
umask 077
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C DEMO_SSH_KEY="$DEMO_SSH_KEY" DEMO_JOB="$JOB_NAME" DEMO_BUILD="$BUILD_NUMBER" DEMO_COMMIT="$gitlabAfter" /usr/bin/node --max-old-space-size=96 --input-type=module <<'NODE'
import fs from 'node:fs';
import path from 'node:path';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const check=(ok)=>{if(!ok)throw Error('TRUSTED_DISPATCH_PACKAGE_REJECTED');};
check(fs.realpathSync('.')===process.cwd()&&fs.statSync('.').uid===process.getuid());
const packed=fs.readFileSync('trusted-package.b64','utf8');
check(packed.length<262144&&/^[A-Za-z0-9+/]+={0,2}$/.test(packed));
const bytes=Buffer.from(packed,'base64');
check(createHash('sha256').update(bytes).digest('hex')==='@TRUSTED_PACKAGE_SHA@');
const contents=JSON.parse(gunzipSync(bytes,{maxOutputLength:1048576}));
check(Object.keys(contents).length>0&&Object.keys(contents).length<120);
fs.mkdirSync('release',{mode:0o700});
for(const [name,text]of Object.entries(contents)){
 check(name.startsWith('infra/')&&name.split('/').every(p=>/^[a-zA-Z0-9_.-]+$/.test(p)&&!['.','..'].includes(p))&&typeof text==='string');
 const file=path.join('release',name);
 fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
 fs.writeFileSync(file,text,{flag:'wx',mode:0o400});
}
const result=spawnSync('/usr/bin/node',['--max-old-space-size=96','release/infra/jenkins/gitlab-push-demo/run-clean.mjs'],
 {env:process.env,stdio:'inherit',timeout:35000});
check(result.status===0);
NODE
'''
              }
              def receipt = readJSON file: 'evidence/jenkins-gitleaks-receipt.json', returnPojo: true
              archiveArtifacts artifacts: 'evidence/**', allowEmptyArchive: false
              if (receipt.job != env.JOB_NAME || receipt.build.toString() != env.BUILD_NUMBER ||
                  receipt.commit != env.gitlabAfter || receipt.classification != 'REAL_CONTROLLED_EXECUTION' ||
                  receipt.scannerExecuted != true || receipt.evaluationCount != 1) {
                error('Invalid build-bound Gitleaks result')
              }
              if (receipt.policyDecision != 'PASS') { error('Gitleaks Policy gate blocked Demo Publish') }
              echo 'GITLEAKS_REAL_GATE PASS runId=' + receipt.runId + ' resultDigest=' + receipt.resultDigest
            } finally { deleteDir() }
          }
        }
      }
    }
    stage('Demo Publish') {
      steps { echo 'Demo Publish reached; no image, GitOps or deployment action' }
    }
  }
}
