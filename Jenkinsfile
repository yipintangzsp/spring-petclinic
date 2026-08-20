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

                    rm -f                       .deploy-started                                              .target-git-revision                                                                    .git-sha                       .git-sha-short                       .change-cause                       .new-revision                       .previous-image                       .previous-revision

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

        stage('Git Promotion') {
            steps {
                withCredentials([
                    sshUserPrivateKey(
                        credentialsId: 'github-petclinic-ssh',
                        keyFileVariable: 'GITHUB_SSH_KEY',
                        usernameVariable: 'GITHUB_SSH_USER'
                    )
                ]) {
                    sh '''
                        set -eu

                        echo "===== GIT IMAGE PROMOTION ====="

                        export GIT_SSH_COMMAND="ssh -i ${GITHUB_SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/var/jenkins_home/.ssh/known_hosts"

                        MANIFEST="k8s/production/petclinic.yaml"
                        SOURCE_GIT_SHA=$(cat .git-sha)

                        echo
                        echo "===== FETCH REMOTE MAIN ====="
                        git fetch origin main

                        REMOTE_MAIN_SHA=$(git rev-parse refs/remotes/origin/main)

                        echo "SOURCE_GIT_SHA=${SOURCE_GIT_SHA}"
                        echo "REMOTE_MAIN_SHA=${REMOTE_MAIN_SHA}"

                        if [ "${SOURCE_GIT_SHA}" != "${REMOTE_MAIN_SHA}" ]; then
                            echo "ERROR: origin/main changed after this build started."
                            echo "Refusing to promote an image built from stale source."
                            exit 1
                        fi

                        echo
                        echo "===== CHECKOUT PROMOTION BRANCH ====="
                        git checkout -B main refs/remotes/origin/main

                        echo
                        echo "===== CURRENT MANIFEST IMAGE ====="
                        grep -E '^[[:space:]]*image:[[:space:]]+10\\.0\\.0\\.3:30050/petclinic/petclinic:' "${MANIFEST}"

                        IMAGE_LINE_COUNT=$(grep -Ec '^[[:space:]]*image:[[:space:]]+10\\.0\\.0\\.3:30050/petclinic/petclinic:' "${MANIFEST}")

                        echo "IMAGE_LINE_COUNT=${IMAGE_LINE_COUNT}"

                        if [ "${IMAGE_LINE_COUNT}" -ne 1 ]; then
                            echo "ERROR: expected exactly one Petclinic image line."
                            exit 1
                        fi

                        echo
                        echo "===== PROMOTE IMAGE ====="

                        sed -i -E \
                          "s#^([[:space:]]*)image:[[:space:]]+10\\.0\\.0\\.3:30050/petclinic/petclinic:.*#\\1image: ${K8S_IMAGE}#" \
                          "${MANIFEST}"

                        echo
                        echo "===== PROMOTED MANIFEST IMAGE ====="
                        grep -E '^[[:space:]]*image:' "${MANIFEST}"

                        echo
                        echo "===== PROMOTION DIFF ====="
                        git diff -- "${MANIFEST}"

                        if git diff --quiet -- "${MANIFEST}"; then
                            echo "GIT_PROMOTION=NO_CHANGE"
                            exit 0
                        fi

                        git config user.name "jenkins-petclinic-ci"
                        git config user.email "jenkins-petclinic-ci@users.noreply.github.com"

                        git add "${MANIFEST}"

                        git commit \
                          -m "cd: promote petclinic image to ${IMAGE_TAG}"

                        echo
                        echo "===== PUSH PROMOTION ====="
                        git push origin main:main

                        echo
                        echo "GIT_PROMOTION=OK"
                        git log -1 --oneline
                    '''
                }
            }
        }

        stage('Wait for ArgoCD Sync') {
            steps {
                sh '''
                    set -eu

                    echo "===== WAIT FOR ARGOCD SYNC ====="

                    TARGET_GIT_SHA=$(git rev-parse HEAD)

                    echo "TARGET_GIT_SHA=${TARGET_GIT_SHA}"
                    echo "TARGET_IMAGE=${K8S_IMAGE}"

                    printf '%s' "${TARGET_GIT_SHA}" > .target-git-revision
                    touch .deploy-started

                    sync_ok=0

                    for attempt in $(seq 1 180); do
                        ARGO_SYNC=$(kubectl -n argocd get application petclinic \
                          -o jsonpath='{.status.sync.status}' 2>/dev/null || true)

                        ARGO_HEALTH=$(kubectl -n argocd get application petclinic \
                          -o jsonpath='{.status.health.status}' 2>/dev/null || true)

                        ARGO_REVISION=$(kubectl -n argocd get application petclinic \
                          -o jsonpath='{.status.sync.revision}' 2>/dev/null || true)

                        echo "ARGO_CHECK=${attempt} SYNC=${ARGO_SYNC} HEALTH=${ARGO_HEALTH} REVISION=${ARGO_REVISION}"

                        if [ "${ARGO_SYNC}" = "Synced" ] && \
                           [ "${ARGO_HEALTH}" = "Healthy" ] && \
                           [ "${ARGO_REVISION}" = "${TARGET_GIT_SHA}" ]; then
                            sync_ok=1
                            break
                        fi

                        sleep 5
                    done

                    if [ "${sync_ok}" -ne 1 ]; then
                        echo "ERROR: ArgoCD did not converge to ${TARGET_GIT_SHA}"
                        exit 1
                    fi

                    echo
                    echo "===== LIVE IMAGE VERIFY ====="

                    LIVE_IMAGE=$(kubectl -n petclinic get deployment petclinic \
                      -o jsonpath='{.spec.template.spec.containers[0].image}')

                    echo "EXPECTED_IMAGE=${K8S_IMAGE}"
                    echo "LIVE_IMAGE=${LIVE_IMAGE}"

                    if [ "${LIVE_IMAGE}" != "${K8S_IMAGE}" ]; then
                        echo "ERROR: live image does not match promoted image"
                        exit 1
                    fi

                    echo
                    echo "ARGOCD_DEPLOYMENT=OK"
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
                    echo 'Collecting GitOps deployment failure diagnostics...'

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

                if (fileExists('.deploy-started')) {
                    echo 'Automatic Kubernetes revision rollback is disabled after ArgoCD cutover.'
                    echo 'Git is now the deployment authority.'
                    echo 'Rollback must be performed through Git and ArgoCD.'
                } else {
                    echo 'Rollback skipped: GitOps deployment was not started.'
                }
            }
        }
    }
}
