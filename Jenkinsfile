pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        timeout(time: 45, unit: 'MINUTES')
    }

    environment {
        MAVEN_OPTS = '-Xmx256m -XX:ActiveProcessorCount=1'
        DOCKER_REGISTRY = '127.0.0.1:13050'
        REGISTRY_API = '10.0.0.3:30050'
        PACKAGE_HTTPS_PROXY = 'http://192.168.1.238:10808'

        IMAGE_REPO = 'petclinic/petclinic'
        IMAGE_TAG = "0.10.0-ci-${BUILD_NUMBER}"

        FULL_IMAGE = "${DOCKER_REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
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
                    rm -f .infra-preflight-before-build.json .sonar-runtime-maintenance.json target/platform/*.json target/surefire-reports/*.xml

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

        stage('Infrastructure Preflight') {
            steps {
                // Maven clean removes target; retain the first gate's evidence outside it.
                sh 'node infra/observability/heavy-lease.mjs acquire'
                sh 'node infra/observability/ensure-sonar-runtime.mjs'
                sh 'node infra/observability/release-preflight.mjs .infra-preflight-before-build.json'
            }
        }

        stage('Test') {
            steps {
                sh '''
                    echo "===== MAVEN TEST ====="
                    node --test infra/observability/*.test.mjs
                    nice -n 10 ./mvnw -B clean test
                    node infra/messaging/pipeline.mjs test
                '''
            }
        }

        stage('Package') {
            steps {
                sh '''
                    echo "===== MAVEN PACKAGE ====="
                    nice -n 10 ./mvnw package -DskipTests

                    echo
                    echo "===== JAR ====="
                    ls -lh target/spring-petclinic-4.0.0-SNAPSHOT.jar
                '''
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    withEnv(['SONAR_HOST_URL=http://sonarqube-sonarqube.sonarqube.svc.cluster.local:9000', 'SONAR_SCANNER_JAVA_OPTS=-Xmx384m -XX:ActiveProcessorCount=1']) {
                        sh '''
                            set -eu
                            node infra/observability/publish-artifacts.mjs sonar-ready
                            node infra/messaging/sonar-diagnostics.mjs || true
                            for attempt in 1 2 3; do
                                if nice -n 10 ./mvnw -B org.sonarsource.scanner.maven:sonar-maven-plugin:5.8.0.7211:sonar \
                                  -Dsonar.projectKey=petclinic \
                                  -Dsonar.scanner.connectTimeout=30 \
                                  -Dsonar.scanner.socketTimeout=120 \
                                  -Dsonar.scanner.responseTimeout=120 \
                                  -Dsonar.qualitygate.wait=true \
                                  -Dsonar.qualitygate.timeout=300 > target/sonar-scanner.log 2>&1; then
                                    cat target/sonar-scanner.log
                                    node infra/messaging/sonar-diagnostics.mjs
                                    exit 0
                                fi
                                cat target/sonar-scanner.log
                                node infra/messaging/sonar-diagnostics.mjs || true
                                if grep -Eiq 'Not authorized|Unauthorized|Forbidden|QUALITY GATE STATUS: FAILED|HTTP[^0-9]*(401|403)' target/sonar-scanner.log; then
                                    exit 1
                                fi
                                if ! grep -Eiq 'Failed to query server version|ConnectException|SocketTimeoutException|Connection refused|Read timed out|Connection reset|connect timed out' target/sonar-scanner.log; then
                                    exit 1
                                fi
                                if [ "$attempt" = 3 ]; then exit 1; fi
                                echo "Sonar service connection failed; bounded retry ${attempt}/2"
                                sleep 15
                            done
                        '''
                    }
                }
            }
        }

        stage('GitLab Source Audit') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'gitlab-creds', usernameVariable: 'GITLAB_USER', passwordVariable: 'GITLAB_TOKEN')]) {
                    sh 'node infra/observability/publish-artifacts.mjs gitlab'
                }
            }
        }

        stage('Multi-Arch Build & Push') {
            steps {
                sh '''
                    echo "===== MULTI-ARCH BUILD & PUSH ====="
                    echo "IMAGE=${FULL_IMAGE}"

                    # Docker uses the host network; Jenkins curl uses the agent pod network.
                    docker pull --platform linux/arm64 \
                      "${DOCKER_REGISTRY}/platform-upgrade/eclipse-temurin:21-jre-local"
                    curl -fsS --retry 6 --retry-delay 5 --retry-connrefused \
                      --connect-timeout 5 --max-time 15 "http://${REGISTRY_API}/v2/"

                    # Use the existing outbound proxy only for these pinned Ubuntu downloads.
                    PACKAGE_HTTPS_PROXY="http://192.168.1.238:10808" \
                      node --max-old-space-size=64 infra/runtime/prepare-security-packages.mjs

                    docker buildx build \
                      --platform linux/amd64,linux/arm64 \
                      -t "${FULL_IMAGE}" \
                      --push \
                      .

                    # Only rebuildable context/JAR build-cache records, under this CI lease.
                    # Keep apt-install cache, tagged images, containers and volumes.
                    docker buildx prune --force --filter type=source.local \
                      > target/platform/build-context-prune.log
                    docker buildx prune --force \
                      --filter 'description~=COPY.target/spring-petclinic-4[.]0[.]0-SNAPSHOT[.]jar.app[.]jar' \
                      > target/platform/build-jar-prune.log
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
                sh 'node infra/observability/record-image.mjs'
            }
        }

        stage('Harbor Push & Scan') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'harbor-creds', usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS')]) {
                    sh '''
                        set -eu
                        node infra/observability/publish-artifacts.mjs harbor-project
                        node infra/observability/publish-artifacts.mjs harbor-copy
                        node infra/observability/publish-artifacts.mjs harbor-scan
                    '''
                }
                script {
                    env.K8S_IMAGE = 'core.harbor.domain/petclinic/petclinic@' + readFile('target/platform/image-digest.txt').trim()
                }
            }
        }

        stage('RabbitMQ Worker Deployment') {
            steps {
                sh 'node infra/messaging/pipeline.mjs deploy'
            }
        }

        stage('Git Promotion') {
            steps {
                sh 'node infra/observability/release-preflight.mjs target/platform/preflight-before-promotion.json'
                withCredentials([usernamePassword(credentialsId: 'gitlab-creds', usernameVariable: 'GITLAB_USER', passwordVariable: 'GITLAB_TOKEN')]) {
                    sh 'node infra/observability/promote-private.mjs'
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

                    sh infra/observability/wait-gitops.sh "${TARGET_GIT_SHA}"
                '''
            }
        }

        stage('Rollout Verify') {
            steps {
                sh '''
                    set -eu
                    echo "===== ROLLOUT STATUS ====="

                    # Same 600-second budget, with ongoing Pod/node/Lease diagnostics
                    # and an exact image + Git revision gate before reporting success.
                    node infra/observability/verify-rollout.mjs "$(cat .target-git-revision)"

                    # Wait for Argo's resource health cache after rollout completion.
                    for attempt in $(seq 1 24); do
                        ARGO_HEALTH=$(kubectl -n argocd get application petclinic -o jsonpath='{.status.health.status}')
                        [ "${ARGO_HEALTH}" = "Healthy" ] && break
                        sleep 5
                    done
                    [ "${ARGO_HEALTH}" = "Healthy" ] || { echo "ERROR: ArgoCD health is ${ARGO_HEALTH}"; exit 1; }

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

        stage('RabbitMQ Release Event') {
            steps {
                sh 'node infra/messaging/pipeline.mjs release'
            }
        }

        stage('Kafka Release Event') {
            steps {
                sh 'node infra/observability/publish-artifacts.mjs kafka'
            }
        }

    }

    post {
        always {
            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                sh 'node infra/observability/heavy-lease.mjs release'
            }
            junit testResults: 'target/surefire-reports/*.xml', allowEmptyResults: true
            archiveArtifacts artifacts: '.infra-preflight-before-build.json,.sonar-runtime-maintenance.json,target/platform/*.json,target/platform/build-*-prune.log', allowEmptyArchive: true
        }
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
