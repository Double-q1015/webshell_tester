FROM tomcat:9-jdk11

# install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# config tomcat
RUN mkdir -p ${CATALINA_HOME}/webapps/ROOT \
    && sed -i 's/52428800/104857600/' ${CATALINA_HOME}/conf/server.xml \
    && chmod -R 755 ${CATALINA_HOME}/webapps \
    && echo "<% out.println(\"healthy\"); %>" > ${CATALINA_HOME}/webapps/ROOT/index.jsp

# set working directory
WORKDIR ${CATALINA_HOME}/webapps

# health check
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/index.jsp || exit 1

# expose port
EXPOSE 8080

# start tomcat
CMD ["catalina.sh", "run"] 