pipeline {
    agent any

    options {
        disableConcurrentBuilds()
    }

    environment {
        DOCKER_REGISTRY = '127.0.0.1:30050'
        REGISTRY_API = '10.0.0.3:30050'
        K8S_REGISTRY = '10.0.0.3:30050'

        IMAGE_REPO = 'petclinic/petclinic'
        IMAGE_TAG = "0.4.0-ci-${BUILD_NUMBER}"

        FULL_IMAGE = "${DOCKER_REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
        K8S_IMAGE = "${K8S_REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
    }

    stages {
        stage('Checkout Info') {
            steps {
                sh '''
                    echo "===== WORKSPACE ====="
                    pwd

                    echo
                    echo "===== CLEAN PIPELINE STATE ====="

                    rm -f                       .deploy-started                                              .previous-revision                                                                     .git-sha                       .git-sha-short

                    echo "Pipeline state cleaned."

                    echo
                    echo "===== GIT ====="
                    git status

                    GIT_SHA=$(git rev-parse HEAD)
                    GIT_SHA_SHORT=$(git rev-parse --short HEAD)

                    echo "GIT_SHA=${GIT_SHA}"
                    echo "GIT_SHA_SHORT=${GIT_SHA_SHORT}"

                    printf '%s' "${GIT_SHA}" > .git-sha
                    printf '%s' "${GIT_SHA_SHORT}" > .git-sha-short
                '''
            }
        }

        stage('Test') {
            steps {
                sh '''
                    echo "===== MAVEN TEST ====="
                    ./mvnw clean test
                '''
            }
        }

        stage('Package') {
            steps {
                sh '''
                    echo "===== MAVEN PACKAGE ====="
                    ./mvnw package -DskipTests

                    echo
                    echo "===== JAR ====="
                    ls -lh target/spring-petclinic-4.0.0-SNAPSHOT.jar
                '''
            }
        }

        stage('Multi-Arch Build & Push') {
            steps {
                sh '''
                    echo "===== MULTI-ARCH BUILD & PUSH ====="
                    echo "IMAGE=${FULL_IMAGE}"

                    docker buildx build \
                      --platform linux/amd64,linux/arm64 \
                      -t "${FULL_IMAGE}" \
                      --push \
                      .
                '''
            }
        }

        stage('Registry Verify') {
            steps {
                sh '''
                    echo "===== REGISTRY TAG VERIFY ====="

                    curl -fsS \
                      "http://${REGISTRY_API}/v2/${IMAGE_REPO}/tags/list"

                    echo
                    echo
                    echo "===== OCI INDEX VERIFY ====="

                    MANIFEST=$(curl -fsS \
                      -H 'Accept: application/vnd.oci.image.index.v1+json' \
                      "http://${REGISTRY_API}/v2/${IMAGE_REPO}/manifests/${IMAGE_TAG}")

                    echo "$MANIFEST"

                    echo
                    echo "===== PLATFORM VERIFY ====="

                    echo "$MANIFEST" |
                      grep -Eq '"architecture"[[:space:]]*:[[:space:]]*"amd64"'
                    echo "linux/amd64: OK"

                    echo "$MANIFEST" |
                      grep -Eq '"architecture"[[:space:]]*:[[:space:]]*"arm64"'
                    echo "linux/arm64: OK"
                '''
            }
        }

        stage('Git Write Dry-Run') {
            steps {
                withCredentials([
                    sshUserPrivateKey(
                        credentialsId: 'github-petclinic-ssh',
                        keyFileVariable: 'GITHUB_SSH_KEY',
                        usernameVariable: 'GITHUB_SSH_USER'
                    )
                ]) {
                    sh '''
                        echo "===== GITHUB WRITE DRY-RUN ====="

                        export GIT_SSH_COMMAND="ssh -i ${GITHUB_SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/var/jenkins_home/.ssh/known_hosts"

                        echo
                        echo "===== FETCH REMOTE MAIN ====="
                        git fetch origin main

                        echo
                        echo "===== PUSH PERMISSION PROBE ====="
                        git push --dry-run origin                           refs/remotes/origin/main:refs/heads/dcp-v1.26-write-probe

                        echo
                        echo "GITHUB_WRITE_DRY_RUN=OK"
                    '''
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                sh '''
                    echo "===== SAVE PREVIOUS IMAGE ====="

                    PREVIOUS_IMAGE=$(kubectl -n petclinic get deployment petclinic \
                      -o jsonpath='{.spec.template.spec.containers[0].image}')

                    echo "PREVIOUS_IMAGE=${PREVIOUS_IMAGE}"

                    if [ -z "${PREVIOUS_IMAGE}" ]; then
                        echo "ERROR: PREVIOUS_IMAGE is empty"
                        exit 1
                    fi

                    GIT_SHA=$(cat .git-sha)
                    GIT_SHA_SHORT=$(cat .git-sha-short)

                    CHANGE_CAUSE="jenkins-build=${BUILD_NUMBER} git=${GIT_SHA_SHORT} image=${IMAGE_TAG}"

                    echo
                    echo "===== RELEASE CANDIDATE ====="
                    echo "BUILD_NUMBER=${BUILD_NUMBER}"
                    echo "GIT_SHA=${GIT_SHA}"
                    echo "IMAGE_TAG=${IMAGE_TAG}"
                    echo "CHANGE_CAUSE=${CHANGE_CAUSE}"

                    echo
                    echo "===== DEPLOY ====="
                    echo "NEW_IMAGE=${K8S_IMAGE}"

                    OLD_REVISION=$(kubectl -n petclinic get deployment petclinic \
                      -o jsonpath='{.metadata.annotations.deployment\\.kubernetes\\.io/revision}')

                    echo "OLD_REVISION=${OLD_REVISION}"

                    if [ -z "${OLD_REVISION}" ]; then
                        echo "ERROR: OLD_REVISION is empty"
                        exit 1
                    fi

                    printf '%s' "${OLD_REVISION}" > .previous-revision

                    echo
                    echo "===== PATCH RELEASE TEMPLATE ====="

                    PATCH=$(cat <<EOF
{
  "spec": {
    "strategy": {
      "type": "RollingUpdate",
      "rollingUpdate": {
        "maxSurge": 3,
        "maxUnavailable": 0
      }
    },
    "template": {
      "metadata": {
        "annotations": {
          "devops.zhanglab.io/git-commit": "${GIT_SHA}",
          "devops.zhanglab.io/jenkins-build": "${BUILD_NUMBER}",
          "devops.zhanglab.io/image-tag": "${IMAGE_TAG}"
        }
      },
      "spec": {
        "containers": [
          {
            "name": "petclinic",
            "image": "${K8S_IMAGE}"
          }
        ]
      }
    }
  }
}
EOF
)

                    echo "${PATCH}"

                    kubectl -n petclinic patch deployment petclinic \
                      --type='strategic' \
                      -p "${PATCH}"

                    touch .deploy-started

                    echo
                    echo "===== WAIT FOR NEW REVISION ====="

                    NEW_REVISION=""

                    for attempt in $(seq 1 30); do
                        NEW_REVISION=$(kubectl -n petclinic get deployment petclinic \
                          -o jsonpath='{.metadata.annotations.deployment\\.kubernetes\\.io/revision}')

                        echo "REVISION_CHECK=${attempt} OLD=${OLD_REVISION} NEW=${NEW_REVISION}"

                        if [ -n "${NEW_REVISION}" ] &&
                           [ "${NEW_REVISION}" != "${OLD_REVISION}" ]; then
                            break
                        fi

                        sleep 2
                    done

                    if [ -z "${NEW_REVISION}" ] ||
                       [ "${NEW_REVISION}" = "${OLD_REVISION}" ]; then
                        echo "ERROR: new Deployment revision was not created"
                        exit 1
                    fi

                    echo
                    echo "===== ANNOTATE NEW REVISION ====="

                    NEW_RS=$(kubectl -n petclinic get rs \
                      -l app=petclinic \
                      -o jsonpath="{range .items[?(@.metadata.annotations.deployment\\.kubernetes\\.io/revision=='${NEW_REVISION}')]}{.metadata.name}{'\\n'}{end}" \
                      | head -1)

                    echo "NEW_REVISION=${NEW_REVISION}"
                    echo "NEW_RS=${NEW_RS}"

                    if [ -z "${NEW_RS}" ]; then
                        echo "ERROR: ReplicaSet for revision ${NEW_REVISION} not found"
                        exit 1
                    fi

                    kubectl -n petclinic annotate replicaset "${NEW_RS}" \
                      kubernetes.io/change-cause="${CHANGE_CAUSE}" \
                      --overwrite
                '''
            }
        }

        stage('Rollout Verify') {
            steps {
                sh '''
                    echo "===== ROLLOUT STATUS ====="

                    kubectl -n petclinic rollout status deployment/petclinic \
                      --timeout=1200s

                    echo
                    echo "===== DEPLOYMENT IMAGE ====="

                    kubectl -n petclinic get deployment petclinic \
                      -o jsonpath='IMAGE={.spec.template.spec.containers[0].image}{"\\n"}'

                    echo
                    echo "===== PODS ====="

                    kubectl -n petclinic get pods \
                      -l app=petclinic \
                      -o wide
                '''
            }
        }

        stage('Health Verify') {
            steps {
                timeout(time: 90, unit: 'SECONDS') {
                    retry(5) {
                        sh '''
                            echo "===== HEALTH VERIFY ====="

                            HEALTH_SCHEME='http'
                            HEALTH_PATH='/actuator/health'
                            HEALTH_URL="${HEALTH_SCHEME}://192.168.1.58${HEALTH_PATH}"

                            echo "HEALTH_PATH=${HEALTH_PATH}"
                            echo "HEALTH_URL=${HEALTH_URL}"

                            curl \
                              --fail \
                              --silent \
                              --show-error \
                              --connect-timeout 5 \
                              --max-time 10 \
                              -H 'Host: petclinic.devops.local' \
                              "${HEALTH_URL}"

                            echo
                        '''
                    }
                }
            }
        }

    }

    post {
        success {
            echo "CI/CD SUCCESS: ${K8S_IMAGE}"
        }

        failure {
            script {
                echo 'CI/CD FAILED'

                if (fileExists('.deploy-started')) {
                    echo 'Collecting failure diagnostics before rollback...'

                    sh '''
                        echo
                        echo "========================================"
                        echo "===== FAILURE DIAGNOSTICS ==============="
                        echo "========================================"

                        echo
                        echo "===== DEPLOYMENT ====="
                        kubectl -n petclinic get deployment petclinic -o wide || true

                        echo
                        echo "===== REPLICASETS ====="
                        kubectl -n petclinic get replicasets                           -l app=petclinic                           -o wide || true

                        echo
                        echo "===== PODS ====="
                        kubectl -n petclinic get pods                           -l app=petclinic                           -o wide || true

                        echo
                        echo "===== DEPLOYMENT DESCRIPTION ====="
                        kubectl -n petclinic describe deployment petclinic || true

                        echo
                        echo "===== POD DESCRIPTIONS ====="
                        for pod in $(kubectl -n petclinic get pods                           -l app=petclinic                           -o name 2>/dev/null); do

                            echo
                            echo "----- ${pod} -----"
                            kubectl -n petclinic describe "${pod}" || true
                        done

                        echo
                        echo "===== CURRENT CONTAINER LOGS ====="
                        for pod in $(kubectl -n petclinic get pods                           -l app=petclinic                           -o name 2>/dev/null); do

                            echo
                            echo "----- ${pod} -----"
                            kubectl -n petclinic logs "${pod}"                               --tail=100 || true
                        done

                        echo
                        echo "===== PREVIOUS CONTAINER LOGS ====="
                        for pod in $(kubectl -n petclinic get pods                           -l app=petclinic                           -o name 2>/dev/null); do

                            echo
                            echo "----- ${pod} -----"
                            kubectl -n petclinic logs "${pod}"                               --previous                               --tail=100 || true
                        done

                        echo
                        echo "===== RECENT EVENTS ====="
                        kubectl -n petclinic get events                           --sort-by=.metadata.creationTimestamp                           | tail -80 || true

                        echo
                        echo "========================================"
                        echo "===== END FAILURE DIAGNOSTICS ==========="
                        echo "========================================"
                    '''
                } else {
                    echo 'Failure diagnostics skipped: deployment was not started.'
                }

                if (fileExists('.deploy-started') &&
                    fileExists('.previous-revision')) {

                    def previousRevision = readFile('.previous-revision').trim()

                    if (previousRevision) {
                        echo "AUTOMATIC ROLLBACK STARTED: revision ${previousRevision}"

                        withEnv(["ROLLBACK_REVISION=${previousRevision}"]) {
                            sh '''
                                echo "===== AUTOMATIC ROLLBACK ====="
                                echo "FAILED_IMAGE=${K8S_IMAGE}"
                                echo "ROLLBACK_REVISION=${ROLLBACK_REVISION}"

                                kubectl -n petclinic rollout undo deployment/petclinic \
                                  --to-revision="${ROLLBACK_REVISION}"

                                kubectl -n petclinic rollout status deployment/petclinic \
                                  --timeout=600s

                                echo
                                echo "===== ROLLBACK IMAGE ====="

                                kubectl -n petclinic get deployment petclinic \
                                  -o jsonpath='IMAGE={.spec.template.spec.containers[0].image}{"\\n"}'

                                echo
                                echo "===== ROLLBACK TEMPLATE METADATA ====="

                                kubectl -n petclinic get deployment petclinic \
                                  -o jsonpath='GIT_COMMIT={.spec.template.metadata.annotations.devops\\.zhanglab\\.io/git-commit}{"\\n"}JENKINS_BUILD={.spec.template.metadata.annotations.devops\\.zhanglab\\.io/jenkins-build}{"\\n"}IMAGE_TAG={.spec.template.metadata.annotations.devops\\.zhanglab\\.io/image-tag}{"\\n"}'

                                echo
                                echo "===== ROLLBACK HEALTH ====="

                                HEALTH_SCHEME='http'
                                HEALTH_URL="${HEALTH_SCHEME}://192.168.1.58/actuator/health"

                                rollback_health_ok=0

                                for attempt in 1 2 3 4 5 6; do
                                    echo
                                    echo "ROLLBACK HEALTH ATTEMPT ${attempt}/6"

                                    if curl \
                                      --fail \
                                      --silent \
                                      --show-error \
                                      --connect-timeout 5 \
                                      --max-time 10 \
                                      -H 'Host: petclinic.devops.local' \
                                      "${HEALTH_URL}"; then

                                        echo
                                        echo "ROLLBACK HEALTH: OK"
                                        rollback_health_ok=1
                                        break
                                    fi

                                    if [ "${attempt}" -lt 6 ]; then
                                        echo "Rollback endpoint not ready yet; retrying in 10 seconds..."
                                        sleep 10
                                    fi
                                done

                                if [ "${rollback_health_ok}" -ne 1 ]; then
                                    echo "ERROR: rollback health verification failed after 6 attempts"
                                    exit 1
                                fi

                                echo
                            '''
                        }

                        echo "AUTOMATIC ROLLBACK SUCCESS: revision ${previousRevision}"
                    } else {
                        echo 'Rollback skipped: previous revision is empty.'
                    }
                } else {
                    echo 'Rollback skipped: deployment was not started.'
                }
            }
        }
    }
}
