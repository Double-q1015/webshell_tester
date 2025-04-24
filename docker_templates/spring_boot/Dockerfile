FROM maven:3.8.4-openjdk-11-slim AS builder

# add build parameters
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# set environment variables
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

# set working directory
WORKDIR /build

# config dns
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf \
    && echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# config maven mirror and proxy
RUN mkdir -p /root/.m2 \
    && echo '<?xml version="1.0" encoding="UTF-8"?>\
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" \
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">\
    <proxies>\
        <proxy>\
            <id>default</id>\
            <active>true</active>\
            <protocol>http</protocol>\
            <host>192.168.2.2</host>\
            <port>7890</port>\
            <nonProxyHosts>localhost|127.0.0.1</nonProxyHosts>\
        </proxy>\
    </proxies>\
    <mirrors>\
        <mirror>\
            <id>aliyunmaven</id>\
            <mirrorOf>*</mirrorOf>\
            <name>阿里云公共仓库</name>\
            <url>https://maven.aliyun.com/repository/public</url>\
        </mirror>\
    </mirrors>\
    <profiles>\
        <profile>\
            <id>jdk-11</id>\
            <activation>\
                <activeByDefault>true</activeByDefault>\
                <jdk>11</jdk>\
            </activation>\
            <repositories>\
                <repository>\
                    <id>aliyun-spring</id>\
                    <url>https://maven.aliyun.com/repository/spring</url>\
                    <releases>\
                        <enabled>true</enabled>\
                    </releases>\
                    <snapshots>\
                        <enabled>true</enabled>\
                    </snapshots>\
                </repository>\
            </repositories>\
        </profile>\
    </profiles>\
</settings>' > /root/.m2/settings.xml

# copy pom.xml
COPY pom.xml .

# pre-download dependencies (add retry and timeout settings)
RUN mvn -B -e dependency:go-offline -Dmaven.wagon.http.retryHandler.count=3 -Dmaven.wagon.http.pool=false -Dmaven.wagon.httpconnectionManager.ttlSeconds=120

# copy source code
COPY src ./src

# build application (add retry and timeout settings)
RUN mvn -B -e clean package -DskipTests -Dmaven.wagon.http.retryHandler.count=3 -Dmaven.wagon.http.pool=false -Dmaven.wagon.httpconnectionManager.ttlSeconds=120

# run environment
FROM openjdk:11-jre-slim

# set run environment variables
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

# install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# set working directory
WORKDIR /app

# copy jar file from builder stage
COPY --from=builder /build/target/*.jar app.jar

# health check
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# expose port
EXPOSE 8080

# start spring boot application
CMD ["java", "-jar", "app.jar"] 