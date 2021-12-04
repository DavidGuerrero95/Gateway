FROM openjdk:12
VOLUME /tmp
EXPOSE 8090
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} Gateway.jar
ENTRYPOINT ["java","-jar","/Gateway.jar"]