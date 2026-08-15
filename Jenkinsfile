pipeline {
    agent any

    parameters {
        booleanParam(
            name: 'FORCE_HEALTH_FAILURE',
            defaultValue: false,
            description: 'DCP v1.19 lab: intentionally fail health verification to test automatic rollback'
        )
    }

    environment {
        DEPLOY_STARTED = 'false'
        PREVIOUS_IMAGE = ''
        HEALTH_PATH = '/actuator/health'
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
                    echo "===== GIT ====="
                    git status
                    git rev-parse --short HEAD
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

                    echo "$MANIFEST" | grep -Eq '"architecture"[[:space:]]*:[[:space:]]*"amd64"'
                    echo "linux/amd64: OK"

                    echo "$MANIFEST" | grep -Eq '"architecture"[[:space:]]*:[[:space:]]*"arm64"'
                    echo "linux/arm64: OK"
                '''
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                script {
                    env.PREVIOUS_IMAGE = sh(
                        script: '''kubectl -n petclinic get deployment petclinic \
                          -o jsonpath='{.spec.template.spec.containers[0].image}' ''',
                        returnStdout: true
                    ).trim()

                    env.DEPLOY_STARTED = 'true'
                }

                sh '''
                    echo "===== DEPLOY ====="
                    echo "PREVIOUS_IMAGE=${PREVIOUS_IMAGE}"
                    echo "NEW_IMAGE=${K8S_IMAGE}"

                    kubectl -n petclinic set image deployment/petclinic \
                      petclinic="${K8S_IMAGE}"
                '''
            }
        }

        stage('Rollout Verify') {
            steps {
                sh '''
                    echo "===== ROLLOUT STATUS ====="

                    kubectl -n petclinic rollout status deployment/petclinic \
                      --timeout=600s

                    echo
                    echo "===== DEPLOYMENT IMAGE ====="

                    kubectl -n petclinic get deploy petclinic \
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
                script {
                    env.HEALTH_PATH = params.FORCE_HEALTH_FAILURE                         ? '/actuator/health-does-not-exist'                         : '/actuator/health'
                }

                sh '''
                    echo "===== HEALTH VERIFY ====="
                    echo "HEALTH_PATH=${HEALTH_PATH}"

                    HEALTH_SCHEME='http'
                    HEALTH_URL="${HEALTH_SCHEME}://192.168.1.58${HEALTH_PATH}"

                    echo "HEALTH_URL=${HEALTH_URL}"

                    curl -fsS \
                      -H 'Host: petclinic.devops.local' \
                      "${HEALTH_URL}"

                    echo
                '''
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

                if (env.DEPLOY_STARTED == 'true' && env.PREVIOUS_IMAGE?.trim()) {
                    echo "AUTOMATIC ROLLBACK STARTED: ${env.PREVIOUS_IMAGE}"

                    sh '''
                        echo "===== AUTOMATIC ROLLBACK ====="
                        echo "FAILED_IMAGE=${K8S_IMAGE}"
                        echo "ROLLBACK_IMAGE=${PREVIOUS_IMAGE}"

                        kubectl -n petclinic set image deployment/petclinic \
                          petclinic="${PREVIOUS_IMAGE}"

                        kubectl -n petclinic rollout status deployment/petclinic \
                          --timeout=600s

                        echo
                        echo "===== ROLLBACK IMAGE ====="

                        kubectl -n petclinic get deployment petclinic \
                          -o jsonpath='IMAGE={.spec.template.spec.containers[0].image}{"\\n"}'

                        echo
                        echo "===== ROLLBACK HEALTH ====="

                        HEALTH_SCHEME='http'
                        HEALTH_URL="${HEALTH_SCHEME}://192.168.1.58/actuator/health"

                        curl -fsS \
                          -H 'Host: petclinic.devops.local' \
                          "${HEALTH_URL}"

                        echo
                    '''

                    echo "AUTOMATIC ROLLBACK SUCCESS: ${env.PREVIOUS_IMAGE}"
                } else {
                    echo 'Rollback skipped: deployment was not started.'
                }
            }
        }
    }
}
