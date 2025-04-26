FROM php:7.4-fpm

# install system dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    libzip-dev \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# install PHP extensions
RUN docker-php-ext-install zip pdo pdo_mysql

# configure Nginx
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

# set working directory
WORKDIR /var/www/html

# expose port
EXPOSE 80

# start service
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"] 