FROM maven:3.8.5-jdk-11 as build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

FROM openjdk:11
WORKDIR /app
COPY --from=build ./app/target/*.jar ./app.jar
COPY --from=build ./app/src/main/resources/application.properties ./application.properties
EXPOSE 8081
ENTRYPOINT java -jar app.jar --spring.config.location=file:./application.properties

LABEL org.opencontainers.image.title="my-oauth2-image"
