FROM node:16-slim

# 安装必要工具
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制package.json和package-lock.json
COPY package*.json ./

# 安装依赖
RUN npm install

# 创建健康检查文件
RUN echo "const express = require('express');\nconst app = express();\n\napp.get('/', (req, res) => {\n    res.send('healthy');\n});\n\napp.listen(3000, () => {\n    console.log('Server running on port 3000');\n});" > index.js

# 健康检查
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# 暴露端口
EXPOSE 3000

# 启动Express应用
CMD ["node", "index.js"] 