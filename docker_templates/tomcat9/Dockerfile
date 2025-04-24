FROM tomcat:9-jdk11

# 安装必要工具
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 配置Tomcat
RUN mkdir -p ${CATALINA_HOME}/webapps/ROOT \
    && sed -i 's/52428800/104857600/' ${CATALINA_HOME}/conf/server.xml \
    && chmod -R 755 ${CATALINA_HOME}/webapps \
    && echo "<% out.println(\"healthy\"); %>" > ${CATALINA_HOME}/webapps/ROOT/index.jsp

# 设置工作目录
WORKDIR ${CATALINA_HOME}/webapps

# 健康检查
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/index.jsp || exit 1

# 暴露端口
EXPOSE 8080

# 启动Tomcat
CMD ["catalina.sh", "run"] 