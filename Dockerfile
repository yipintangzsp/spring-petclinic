ARG TARGETARCH

FROM scratch AS security-amd64
ADD --checksum=sha256:3ff73e121f6cd4f19e80ab4329dfd914108b3936c9db3708200203a9b245b34d https://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl3t64_3.5.5-1ubuntu3.7_amd64.deb /libssl3t64_3.5.5-1ubuntu3.7_amd64.deb
ADD --checksum=sha256:6965aafe69e0a49ef34d2e26f8e83d09d1c6037b7e9ee37f19b292a3c6851621 https://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_3.5.5-1ubuntu3.7_amd64.deb /openssl_3.5.5-1ubuntu3.7_amd64.deb
ADD --checksum=sha256:51cf418571059831096abd40e0bd5debaa1ae48a6f8d87d9e4e5f7f12aa4db52 https://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl-provider-legacy_3.5.5-1ubuntu3.7_amd64.deb /openssl-provider-legacy_3.5.5-1ubuntu3.7_amd64.deb

FROM scratch AS security-arm64
ADD --checksum=sha256:9fe87b6beec5de636a70e4fb6076517a39f5053c7e23e628c9459b94f85c75ff https://ports.ubuntu.com/ubuntu-ports/pool/main/o/openssl/libssl3t64_3.5.5-1ubuntu3.7_arm64.deb /libssl3t64_3.5.5-1ubuntu3.7_arm64.deb
ADD --checksum=sha256:623ea7ec0eb80da3f40e89e3318a4e82d4c64146d206c90cabbce6998d822fa8 https://ports.ubuntu.com/ubuntu-ports/pool/main/o/openssl/openssl_3.5.5-1ubuntu3.7_arm64.deb /openssl_3.5.5-1ubuntu3.7_arm64.deb
ADD --checksum=sha256:757ec89120fe3f418a842342b3a0c596b89b0e3fb0ba770347dda1219f219bbd https://ports.ubuntu.com/ubuntu-ports/pool/main/o/openssl/openssl-provider-legacy_3.5.5-1ubuntu3.7_arm64.deb /openssl-provider-legacy_3.5.5-1ubuntu3.7_arm64.deb

FROM security-${TARGETARCH} AS security-packages

FROM 127.0.0.1:13050/platform-upgrade/eclipse-temurin:21-jre-local@sha256:69bc3d67c3f9f788cbc235723fdaf8a569015125590a2f7d9ed455537a1f4312

COPY --from=security-packages / /tmp/security-packages/
RUN dpkg -i /tmp/security-packages/*.deb \
    && rm -rf /tmp/security-packages \
    && rm -f /usr/bin/pebble

WORKDIR /app

COPY target/spring-petclinic-4.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
