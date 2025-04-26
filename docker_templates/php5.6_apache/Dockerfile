FROM php:5.6-apache

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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql mysqli zip \
    && docker-php-ext-configure gd --with-freetype-dir=/usr/include/ --with-jpeg-dir=/usr/include/ \
    && docker-php-ext-install gd

# configure Apache
RUN a2enmod rewrite \
    && echo "ServerName localhost" >> /etc/apache2/apache2.conf \
    && echo '<Directory /var/www/html>\n\
    Options Indexes FollowSymLinks\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>' > /etc/apache2/conf-available/custom.conf \
    && a2enconf custom

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

# start Apache
CMD ["apache2-foreground"] 