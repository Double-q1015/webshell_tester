FROM php:7.4-apache

# 安装必要工具
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 配置Apache
RUN a2enmod rewrite \
    && echo "ServerName localhost" >> /etc/apache2/apache2.conf \
    && echo '<Directory /var/www/html>\n\
    Options Indexes FollowSymLinks\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>' > /etc/apache2/conf-available/custom.conf \
    && a2enconf custom

# 设置工作目录
WORKDIR /var/www/html

# 设置目录权限
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# 健康检查
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost/health.php || exit 1

# 暴露端口
EXPOSE 80

# 启动Apache
CMD ["apache2-foreground"] 