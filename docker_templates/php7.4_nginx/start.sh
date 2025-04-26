#!/bin/bash

# start PHP-FPM
php-fpm &

# start Nginx
nginx -g "daemon off;" 