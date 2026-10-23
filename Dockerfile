ARG TARGETARCH

FROM scratch AS security-packages
ARG TARGETARCH
COPY target/security-packages/${TARGETARCH}/ /

FROM 127.0.0.1:13050/platform-upgrade/eclipse-temurin:21-jre-local@sha256:69bc3d67c3f9f788cbc235723fdaf8a569015125590a2f7d9ed455537a1f4312

COPY --from=security-packages / /tmp/security-packages/
# Resolve Pre-Depends from the verified local bundle; never fetch unpinned packages.
RUN --network=none DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove --no-install-recommends /tmp/security-packages/*.deb \
    && test -z "$(dpkg --audit)" \
    && rm -rf /tmp/security-packages \
    && rm -f /usr/bin/pebble

WORKDIR /app

COPY target/spring-petclinic-4.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
