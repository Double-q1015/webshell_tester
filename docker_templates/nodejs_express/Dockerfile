FROM node:16-slim

# install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# set working directory
WORKDIR /app

# copy package.json and package-lock.json
COPY package*.json ./

# install dependencies
RUN npm install

# create health check file
RUN echo "const express = require('express');\nconst app = express();\n\napp.get('/', (req, res) => {\n    res.send('healthy');\n});\n\napp.listen(3000, () => {\n    console.log('Server running on port 3000');\n});" > index.js

# health check
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# expose port
EXPOSE 3000

# start express application
CMD ["node", "index.js"] 