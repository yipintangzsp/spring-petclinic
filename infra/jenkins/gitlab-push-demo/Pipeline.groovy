// Trusted inline definition: no agent, checkout, shell, credential or publication.
pipeline {
  agent none
  options {
    skipDefaultCheckout(true)
    disableConcurrentBuilds()
    disableRestartFromStage()
    timeout(time: 2, unit: 'MINUTES')
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
    stage('Non-production Verification') {
      steps { echo 'SUCCESS: fixed documentation push verified; no checkout, shell, scanner, build, registry or deployment action' }
    }
  }
}
