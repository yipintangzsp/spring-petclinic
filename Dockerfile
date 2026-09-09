FROM 127.0.0.1:30050/petclinic/petclinic:0.4.0-ci-61

WORKDIR /app

COPY target/spring-petclinic-4.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
