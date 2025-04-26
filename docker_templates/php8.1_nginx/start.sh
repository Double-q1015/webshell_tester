#!/bin/bash

# start PHP-FPM
service php8.1-fpm start

# start Nginx
nginx -g "daemon off;" 