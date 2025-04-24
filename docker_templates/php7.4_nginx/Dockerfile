FROM php:7.4-fpm

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    nginx \
    libzip-dev \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 安装 PHP 扩展
RUN docker-php-ext-install zip pdo pdo_mysql

# 配置 Nginx
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

# 设置工作目录
WORKDIR /var/www/html

# 暴露端口
EXPOSE 80

# 启动服务
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"] 