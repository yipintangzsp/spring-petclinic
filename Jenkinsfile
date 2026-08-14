pipeline {
    agent any

    environment {
        DOCKER_REGISTRY = '127.0.0.1:30050'
        REGISTRY_API = '10.0.0.3:30050'

        IMAGE_REPO = 'petclinic/petclinic'
        IMAGE_TAG = "0.4.0-ci-${BUILD_NUMBER}"

        FULL_IMAGE = "${DOCKER_REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
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
    }

    post {
        success {
            echo "MULTI-ARCH CI SUCCESS: ${FULL_IMAGE}"
        }

        failure {
            echo 'MULTI-ARCH CI FAILED'
        }
    }
}
