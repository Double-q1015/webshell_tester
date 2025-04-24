#!/bin/bash

# 启动 PHP-FPM
service php8.1-fpm start

# 启动 Nginx
nginx -g "daemon off;" 