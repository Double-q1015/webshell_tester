FROM maven:3.8.4-openjdk-11-slim AS builder

# 添加构建参数
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# 设置环境变量
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

# 设置工作目录
WORKDIR /build

# 配置DNS和网络
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf \
    && echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# 配置Maven镜像和代理
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

# 复制pom.xml
COPY pom.xml .

# 预下载依赖（添加重试和超时设置）
RUN mvn -B -e dependency:go-offline -Dmaven.wagon.http.retryHandler.count=3 -Dmaven.wagon.http.pool=false -Dmaven.wagon.httpconnectionManager.ttlSeconds=120

# 复制源代码
COPY src ./src

# 构建应用（添加重试和超时设置）
RUN mvn -B -e clean package -DskipTests -Dmaven.wagon.http.retryHandler.count=3 -Dmaven.wagon.http.pool=false -Dmaven.wagon.httpconnectionManager.ttlSeconds=120

# 运行环境
FROM openjdk:11-jre-slim

# 设置运行时代理环境变量
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

# 安装必要工具
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 从构建阶段复制jar文件
COPY --from=builder /build/target/*.jar app.jar

# 健康检查
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# 暴露端口
EXPOSE 8080

# 启动Spring Boot应用
CMD ["java", "-jar", "app.jar"] 