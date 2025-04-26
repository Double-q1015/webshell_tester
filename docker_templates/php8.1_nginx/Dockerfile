FROM php:8.1-fpm

# configure DNS
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf \
    && echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    libxml2-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libzip-dev \
    nginx \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql mysqli zip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install gd \
    && docker-php-ext-install opcache

# configure PHP-FPM
RUN sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' /usr/local/etc/php/php.ini \
    && sed -i 's/memory_limit = 128M/memory_limit = 256M/' /usr/local/etc/php/php.ini \
    && sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 10M/' /usr/local/etc/php/php.ini \
    && sed -i 's/post_max_size = 8M/post_max_size = 10M/' /usr/local/etc/php/php.ini

# configure Nginx
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

# set working directory
WORKDIR /var/www/html

# set directory permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# health check
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost/health.php || exit 1

# expose port
EXPOSE 80

# start service
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"] 